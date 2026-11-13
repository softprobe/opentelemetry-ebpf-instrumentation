// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type checkoutResponse struct {
	Service      string            `json:"service"`
	ID           int64             `json:"id"`
	Code         string            `json:"code"`
	Title        string            `json:"title"`
	PackageCents int               `json:"package_cents"`
	InStock      bool              `json:"in_stock"`
	RouteCode    string            `json:"route_code"`
	Carrier      string            `json:"carrier"`
	FareCents    int               `json:"fare_cents"`
	Cabin        string            `json:"cabin"`
	BaggageNote  *string           `json:"baggage_note"`
	MissWasNil   bool              `json:"miss_was_nil"`
	Cart         map[string]string `json:"cart"`
	TotalCents   int               `json:"total_cents"`
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	ctx := context.Background()

	pgDSN := envOr("PG_DSN", "postgres://postgres:postgres@multilang-postgres:5432/traveldb?sslmode=disable")
	pgCfg, err := pgxpool.ParseConfig(pgDSN)
	if err != nil {
		panic(err)
	}
	pgCfg.MaxConns = 24
	pgCfg.MinConns = 0
	pgPool, err := pgxpool.NewWithConfig(ctx, pgCfg)
	if err != nil {
		panic(err)
	}
	defer pgPool.Close()

	mysqlDSN := envOr("MYSQL_DSN", "root:rootpass@tcp(multilang-mysql:3306)/otadb")
	mysqlDB, err := sql.Open("mysql", mysqlDSN)
	if err != nil {
		panic(err)
	}
	mysqlDB.SetMaxOpenConns(24)
	mysqlDB.SetMaxIdleConns(24)
	defer mysqlDB.Close()

	redisAddr := envOr("REDIS_ADDR", "multilang-redis:6379")
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		PoolSize: 24,
	})
	defer rdb.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	mux.HandleFunc("GET /api/go/checkout/{id}", func(w http.ResponseWriter, r *http.Request) {
		reqCtx := r.Context()
		idVal, parseErr := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if parseErr != nil || idVal <= 0 {
			http.Error(w, `{"error":"invalid id"}`, http.StatusBadRequest)
			return
		}

		var (
			itemID       int64
			code         string
			title        string
			packageCents int
			inStock      bool
		)
		if qErr := pgPool.QueryRow(
			reqCtx,
			"SELECT id, code, title, price_cents, in_stock FROM catalog_items WHERE id = $1",
			idVal,
		).Scan(&itemID, &code, &title, &packageCents, &inStock); qErr != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, qErr.Error()), http.StatusInternalServerError)
			return
		}

		var (
			fareID      int64
			routeCode   string
			carrier     string
			fareCents   int
			cabin       string
			baggageNote sql.NullString
		)
		if mErr := mysqlDB.QueryRowContext(
			reqCtx,
			"SELECT id, route_code, carrier, fare_cents, cabin, baggage_note FROM flight_fares WHERE id = ?",
			idVal,
		).Scan(&fareID, &routeCode, &carrier, &fareCents, &cabin, &baggageNote); mErr != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, mErr.Error()), http.StatusInternalServerError)
			return
		}
		_ = fareID

		missKey := fmt.Sprintf("go:miss:%d", idVal)
		_, missErr := rdb.Get(reqCtx, missKey).Result()
		missWasNil := errors.Is(missErr, redis.Nil)
		if missErr != nil && !missWasNil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, missErr.Error()), http.StatusInternalServerError)
			return
		}

		cartKey := fmt.Sprintf("go:cart:%d", idVal)
		if hErr := rdb.HSet(reqCtx, cartKey, "code", code, "route", routeCode).Err(); hErr != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, hErr.Error()), http.StatusInternalServerError)
			return
		}
		cartMap, hGetErr := rdb.HGetAll(reqCtx, cartKey).Result()
		if hGetErr != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, hGetErr.Error()), http.StatusInternalServerError)
			return
		}

		var notePtr *string
		if baggageNote.Valid {
			v := baggageNote.String
			notePtr = &v
		}

		resp := checkoutResponse{
			Service:      "multilang-go",
			ID:           itemID,
			Code:         code,
			Title:        title,
			PackageCents: packageCents,
			InStock:      inStock,
			RouteCode:    routeCode,
			Carrier:      carrier,
			FareCents:    fareCents,
			Cabin:        cabin,
			BaggageNote:  notePtr,
			MissWasNil:   missWasNil,
			Cart:         cartMap,
			TotalCents:   packageCents + fareCents,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{
		Addr:              ":8083",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

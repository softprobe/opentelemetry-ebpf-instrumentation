import express from "express";
import pg from "pg";
import mysql from "mysql2/promise";

const { Pool } = pg;

const pgPool = new Pool({
  host: process.env.PG_HOST || "multilang-postgres",
  port: Number(process.env.PG_PORT || 5432),
  user: process.env.PG_USER || "postgres",
  password: process.env.PG_PASSWORD || "postgres",
  database: process.env.PG_DB || "traveldb",
  max: 24,
  ssl: false,
});

const mysqlPool = mysql.createPool({
  host: process.env.MYSQL_HOST || "multilang-mysql",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || "root",
  password: process.env.MYSQL_PASSWORD || "rootpass",
  database: process.env.MYSQL_DB || "otadb",
  waitForConnections: true,
  connectionLimit: 24,
});

const app = express();
app.disable("etag");
app.disable("x-powered-by");

app.get("/healthz", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/node/itinerary/:itemId", async (req, res) => {
  try {
    const itemId = Number(req.params.itemId);
    const pgRes = await pgPool.query(
      "SELECT id, code, title, price_cents, in_stock FROM catalog_items WHERE id = $1",
      [itemId],
    );
    if (pgRes.rows.length === 0) {
      res.status(404).json({ error: "item not found" });
      return;
    }

    const [fareRows] = await mysqlPool.execute(
      "SELECT id, route_code, carrier, fare_cents, cabin, baggage_note FROM flight_fares WHERE id = ? AND fare_cents > ?",
      [itemId, 100],
    );
    if (!Array.isArray(fareRows) || fareRows.length === 0) {
      res.status(404).json({ error: "fare not found" });
      return;
    }

    const item = pgRes.rows[0];
    const fare = fareRows[0];
    res.json({
      service: "multilang-node",
      id: Number(item.id),
      code: item.code,
      title: item.title,
      package_cents: Number(item.price_cents),
      in_stock: Boolean(item.in_stock),
      route_code: fare.route_code,
      carrier: fare.carrier,
      fare_cents: Number(fare.fare_cents),
      cabin: fare.cabin,
      baggage_note: fare.baggage_note ?? null,
      bundle_cents: Number(item.price_cents) + Number(fare.fare_cents),
    });
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) });
  }
});

const port = Number(process.env.PORT || 8082);
app.listen(port, "0.0.0.0");

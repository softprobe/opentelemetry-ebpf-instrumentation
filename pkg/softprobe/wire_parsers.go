// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	pgOIDBool        uint32 = 16
	pgOIDBytea       uint32 = 17
	pgOIDName        uint32 = 19
	pgOIDInt8        uint32 = 20
	pgOIDInt2        uint32 = 21
	pgOIDInt4        uint32 = 23
	pgOIDText        uint32 = 25
	pgOIDOID         uint32 = 26
	pgOIDJSON        uint32 = 114
	pgOIDFloat4      uint32 = 700
	pgOIDFloat8      uint32 = 701
	pgOIDUnknown     uint32 = 705
	pgOIDBpchar      uint32 = 1042
	pgOIDVarchar     uint32 = 1043
	pgOIDDate        uint32 = 1082
	pgOIDTimestamp   uint32 = 1114
	pgOIDTimestamptz uint32 = 1184
	pgOIDNumeric     uint32 = 1700
	pgOIDUUID        uint32 = 2950
	pgOIDJSONB       uint32 = 3802
)

const (
	mysqlTypeDecimal    uint8 = 0x00
	mysqlTypeTiny       uint8 = 0x01
	mysqlTypeShort      uint8 = 0x02
	mysqlTypeLong       uint8 = 0x03
	mysqlTypeFloat      uint8 = 0x04
	mysqlTypeDouble     uint8 = 0x05
	mysqlTypeNull       uint8 = 0x06
	mysqlTypeTimestamp  uint8 = 0x07
	mysqlTypeLongLong   uint8 = 0x08
	mysqlTypeInt24      uint8 = 0x09
	mysqlTypeDate       uint8 = 0x0a
	mysqlTypeTime       uint8 = 0x0b
	mysqlTypeDatetime   uint8 = 0x0c
	mysqlTypeYear       uint8 = 0x0d
	mysqlTypeVarchar    uint8 = 0x0f
	mysqlTypeBit        uint8 = 0x10
	mysqlTypeJSON       uint8 = 0xf5
	mysqlTypeNewDecimal uint8 = 0xf6
	mysqlTypeTinyBlob   uint8 = 0xf9
	mysqlTypeMediumBlob uint8 = 0xfa
	mysqlTypeLongBlob   uint8 = 0xfb
	mysqlTypeBlob       uint8 = 0xfc
	mysqlTypeVarString  uint8 = 0xfd
	mysqlTypeString     uint8 = 0xfe

	mysqlFlagUnsigned uint16 = 0x0020
	mysqlCharsetUTF8  uint16 = 45
)

var pgEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func ParsePostgresWireRequestParams(buf []byte) []any {
	var parsedOIDs map[string][]uint32
	pos := 0
	for pos+5 <= len(buf) {
		msgType := buf[pos]
		msgLen := int(binary.BigEndian.Uint32(buf[pos+1 : pos+5]))
		if msgLen < 4 || pos+1+msgLen > len(buf) {
			break
		}
		payload := buf[pos+5 : pos+1+msgLen]
		pos += 1 + msgLen

		if msgType == 'P' {
			stmtName, p, ok := readCString(payload, 0)
			if !ok {
				continue
			}
			_, p, ok = readCString(payload, p)
			if !ok || p+2 > len(payload) {
				continue
			}
			nOIDs := int(binary.BigEndian.Uint16(payload[p : p+2]))
			p += 2
			if nOIDs > 0 && nOIDs <= 4096 && p+nOIDs*4 <= len(payload) {
				oids := make([]uint32, nOIDs)
				for i := range nOIDs {
					oids[i] = binary.BigEndian.Uint32(payload[p+i*4 : p+(i+1)*4])
				}
				if parsedOIDs == nil {
					parsedOIDs = make(map[string][]uint32)
				}
				parsedOIDs[stmtName] = oids
			}
			continue
		}

		if msgType != 'B' {
			continue
		}
		_, _, params, _, ok := parsePostgresBindPayload(payload, func(name string) []uint32 {
			if parsedOIDs == nil {
				return nil
			}
			return parsedOIDs[name]
		})
		if !ok {
			return nil
		}
		return params
	}
	return nil
}

func parsePostgresBindPayload(payload []byte, lookupParamOIDs func(stmtName string) []uint32) (string, string, []any, []int16, bool) {
	portalName, p, ok := readCString(payload, 0)
	if !ok {
		return "", "", nil, nil, false
	}
	stmtName, p, ok := readCString(payload, p)
	if !ok || p+2 > len(payload) {
		return "", "", nil, nil, false
	}
	numFormats := int(binary.BigEndian.Uint16(payload[p : p+2]))
	p += 2
	if numFormats < 0 || numFormats > 4096 || p+numFormats*2 > len(payload) {
		return "", "", nil, nil, false
	}
	paramFormats := make([]int16, numFormats)
	for i := range numFormats {
		paramFormats[i] = int16(binary.BigEndian.Uint16(payload[p+i*2 : p+(i+1)*2]))
	}
	p += numFormats * 2

	if p+2 > len(payload) {
		return "", "", nil, nil, false
	}
	numParams := int(binary.BigEndian.Uint16(payload[p : p+2]))
	p += 2
	if numParams < 0 || numParams > 4096 {
		return "", "", nil, nil, false
	}
	var paramOIDs []uint32
	if lookupParamOIDs != nil {
		paramOIDs = lookupParamOIDs(stmtName)
	}
	params := make([]any, 0, numParams)
	for i := range numParams {
		if p+4 > len(payload) {
			return portalName, stmtName, params, nil, true
		}
		valLen := int(int32(binary.BigEndian.Uint32(payload[p : p+4])))
		p += 4
		if valLen < 0 {
			params = append(params, nil)
			continue
		}
		if p+valLen > len(payload) {
			return portalName, stmtName, params, nil, true
		}
		fmtCode := pgEffectiveFormat(paramFormats, i)
		var oid uint32
		if i < len(paramOIDs) {
			oid = paramOIDs[i]
		}
		params = append(params, decodePostgresWireValue(payload[p:p+valLen], fmtCode, oid))
		p += valLen
	}

	var resultFormats []int16
	if p+2 <= len(payload) {
		numResFormats := int(binary.BigEndian.Uint16(payload[p : p+2]))
		p += 2
		if numResFormats > 0 && numResFormats <= 4096 && p+numResFormats*2 <= len(payload) {
			resultFormats = make([]int16, numResFormats)
			for i := range numResFormats {
				resultFormats[i] = int16(binary.BigEndian.Uint16(payload[p+i*2 : p+(i+1)*2]))
			}
		}
	}
	return portalName, stmtName, params, resultFormats, true
}

func pgEffectiveFormat(formats []int16, idx int) int16 {
	if len(formats) == 0 {
		return 0
	}
	if len(formats) == 1 {
		return formats[0]
	}
	if idx >= 0 && idx < len(formats) {
		return formats[idx]
	}
	return 0
}

func decodePostgresWireValue(raw []byte, formatCode int16, oid uint32) string {
	if formatCode == 0 {
		return string(raw)
	}
	switch oid {
	case pgOIDBool:
		if len(raw) == 1 {
			if raw[0] != 0 {
				return "t"
			}
			return "f"
		}
	case pgOIDBytea:
		return `\x` + hex.EncodeToString(raw)
	case pgOIDInt2:
		if len(raw) == 2 {
			return strconv.FormatInt(int64(int16(binary.BigEndian.Uint16(raw))), 10)
		}
	case pgOIDInt4, pgOIDOID:
		if len(raw) == 4 {
			return strconv.FormatInt(int64(int32(binary.BigEndian.Uint32(raw))), 10)
		}
	case pgOIDInt8:
		if len(raw) == 8 {
			return strconv.FormatInt(int64(binary.BigEndian.Uint64(raw)), 10)
		}
	case pgOIDFloat4:
		if len(raw) == 4 {
			return strconv.FormatFloat(float64(math.Float32frombits(binary.BigEndian.Uint32(raw))), 'g', -1, 32)
		}
	case pgOIDFloat8:
		if len(raw) == 8 {
			return strconv.FormatFloat(math.Float64frombits(binary.BigEndian.Uint64(raw)), 'g', -1, 64)
		}
	case pgOIDText, pgOIDVarchar, pgOIDBpchar, pgOIDName, pgOIDJSON, pgOIDUnknown:
		return string(raw)
	case pgOIDJSONB:
		if len(raw) >= 1 && raw[0] == 1 {
			return string(raw[1:])
		}
		return string(raw)
	case pgOIDUUID:
		if len(raw) == 16 {
			return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
		}
	case pgOIDDate:
		if len(raw) == 4 {
			days := int(int32(binary.BigEndian.Uint32(raw)))
			return pgEpoch.AddDate(0, 0, days).Format("2006-01-02")
		}
	case pgOIDTimestamp, pgOIDTimestamptz:
		if len(raw) == 8 {
			usec := int64(binary.BigEndian.Uint64(raw))
			ts := pgEpoch.Add(time.Duration(usec) * time.Microsecond).UTC()
			if oid == pgOIDTimestamptz {
				return ts.Format("2006-01-02 15:04:05.999999+00")
			}
			return ts.Format("2006-01-02 15:04:05.999999")
		}
	case pgOIDNumeric:
		if s, ok := decodePostgresNumeric(raw); ok {
			return s
		}
	}

	if utf8.Valid(raw) && isPrintableUTF8(raw) {
		return string(raw)
	}
	return `\x` + hex.EncodeToString(raw)
}

func isPrintableUTF8(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

func decodePostgresNumeric(raw []byte) (string, bool) {
	if len(raw) < 8 {
		return "", false
	}
	ndigits := int(int16(binary.BigEndian.Uint16(raw[0:2])))
	weight := int(int16(binary.BigEndian.Uint16(raw[2:4])))
	sign := binary.BigEndian.Uint16(raw[4:6])
	dscale := int(int16(binary.BigEndian.Uint16(raw[6:8])))
	if ndigits < 0 || 8+ndigits*2 > len(raw) {
		return "", false
	}
	if sign == 0xc000 {
		return "NaN", true
	}
	if ndigits == 0 {
		if dscale > 0 {
			return "0." + strings.Repeat("0", dscale), true
		}
		return "0", true
	}
	digits := make([]int, ndigits)
	for i := range ndigits {
		digits[i] = int(binary.BigEndian.Uint16(raw[8+i*2 : 10+i*2]))
	}
	var sb strings.Builder
	if sign == 0x4000 {
		sb.WriteByte('-')
	}
	if weight < 0 {
		sb.WriteByte('0')
	} else {
		for i := 0; i <= weight; i++ {
			d := 0
			if i < len(digits) {
				d = digits[i]
			}
			if i == 0 {
				sb.WriteString(strconv.Itoa(d))
			} else {
				fmt.Fprintf(&sb, "%04d", d)
			}
		}
	}
	if dscale > 0 {
		sb.WriteByte('.')
		var frac strings.Builder
		for i := weight + 1; frac.Len() < dscale; i++ {
			if i < 0 {
				frac.WriteString("0000")
				continue
			}
			d := 0
			if i < len(digits) {
				d = digits[i]
			}
			fmt.Fprintf(&frac, "%04d", d)
		}
		fracStr := frac.String()
		if len(fracStr) > dscale {
			fracStr = fracStr[:dscale]
		}
		sb.WriteString(fracStr)
	}
	return sb.String(), true
}

func ParsePostgresWireResponse(buf []byte) *DatabaseResult {
	return parsePostgresWireResponseWithFormats(buf, nil, nil)
}

func parsePostgresWireResponseWithFormats(buf []byte, fallbackCols []DatabaseColumn, resultFormats []int16) *DatabaseResult {
	if len(buf) < 5 {
		return nil
	}
	var res DatabaseResult
	if len(fallbackCols) > 0 {
		res.Columns = append([]DatabaseColumn(nil), fallbackCols...)
	}
	var colFormats []int16
	parsedAny := false
	pos := 0
	for pos+5 <= len(buf) {
		msgType := buf[pos]
		msgLen := int(binary.BigEndian.Uint32(buf[pos+1 : pos+5]))
		if msgLen < 4 || pos+1+msgLen > len(buf) {
			break
		}
		payload := buf[pos+5 : pos+1+msgLen]
		pos += 1 + msgLen

		switch msgType {
		case 'T':
			cols, fmts, ok := parsePostgresRowDescription(payload)
			if ok {
				res.Columns = cols
				colFormats = fmts
				parsedAny = true
			}
		case 'D':
			if len(payload) < 2 {
				continue
			}
			colCount := int(binary.BigEndian.Uint16(payload[:2]))
			p := 2
			row := make([]any, 0, min(colCount, 512))
			for colIdx := range colCount {
				if p+4 > len(payload) {
					break
				}
				valLen := int(int32(binary.BigEndian.Uint32(payload[p : p+4])))
				p += 4
				if valLen < 0 {
					row = append(row, nil)
					continue
				}
				if p+valLen > len(payload) {
					break
				}
				fmtCode := pgEffectiveFormat(resultFormats, colIdx)
				if colIdx < len(colFormats) {
					fmtCode = colFormats[colIdx]
				}
				var oid uint32
				if colIdx < len(res.Columns) {
					oid = res.Columns[colIdx].TypeOID
				}
				row = append(row, decodePostgresWireValue(payload[p:p+valLen], fmtCode, oid))
				p += valLen
			}
			res.Rows = append(res.Rows, row)
			parsedAny = true
		case 'C':
			tag, _, ok := readCString(payload, 0)
			if ok {
				res.CommandTag = tag
				res.RowsAffected = parseTrailingAffectedCount(tag)
				parsedAny = true
			}
		case 'E':
			p := 0
			for p < len(payload) && payload[p] != 0 {
				fieldType := payload[p]
				val, nextP, ok := readCString(payload, p+1)
				if !ok {
					break
				}
				switch fieldType {
				case 'C':
					res.ErrorCode = val
				case 'M':
					res.ErrorMessage = val
				}
				p = nextP
			}
			parsedAny = true
		}
	}
	if !parsedAny {
		return nil
	}
	return &res
}

func parsePostgresRowDescription(payload []byte) ([]DatabaseColumn, []int16, bool) {
	if len(payload) < 2 {
		return nil, nil, false
	}
	fieldCount := int(binary.BigEndian.Uint16(payload[:2]))
	p := 2
	cols := make([]DatabaseColumn, 0, min(fieldCount, 512))
	fmts := make([]int16, 0, min(fieldCount, 512))
	for range fieldCount {
		name, nextP, ok := readCString(payload, p)
		if !ok || nextP+18 > len(payload) {
			return nil, nil, false
		}
		typeOID := binary.BigEndian.Uint32(payload[nextP+6 : nextP+10])
		fmtCode := int16(binary.BigEndian.Uint16(payload[nextP+16 : nextP+18]))
		cols = append(cols, DatabaseColumn{
			Name:    name,
			TypeOID: typeOID,
		})
		fmts = append(fmts, fmtCode)
		p = nextP + 18
	}
	return cols, fmts, true
}

func ParseMySQLWireResponse(buf []byte) *DatabaseResult {
	if len(buf) < 5 {
		return nil
	}
	pktPayload, nextPos, ok := readMySQLPacket(buf, 0)
	if !ok || len(pktPayload) == 0 {
		return nil
	}

	switch pktPayload[0] {
	case 0x00:
		affected, p, ok := readMySQLLenEncInt(pktPayload, 1)
		if !ok {
			return &DatabaseResult{}
		}
		lastID, _, _ := readMySQLLenEncInt(pktPayload, p)
		return &DatabaseResult{
			RowsAffected: int64(affected),
			LastInsertID: int64(lastID),
		}
	case 0xff:
		if len(pktPayload) < 3 {
			return &DatabaseResult{ErrorMessage: "MySQL error"}
		}
		code := binary.LittleEndian.Uint16(pktPayload[1:3])
		msgPos := 3
		if msgPos < len(pktPayload) && pktPayload[msgPos] == '#' && msgPos+6 <= len(pktPayload) {
			msgPos += 6
		}
		return &DatabaseResult{
			ErrorCode:    strconv.Itoa(int(code)),
			ErrorMessage: string(pktPayload[msgPos:]),
		}
	}

	colCountU64, _, ok := readMySQLLenEncInt(pktPayload, 0)
	if !ok || colCountU64 == 0 || colCountU64 > 1024 {
		return nil
	}
	colCount := int(colCountU64)
	cols := make([]DatabaseColumn, 0, colCount)
	pos := nextPos
	for range colCount {
		colPkt, np, ok := readMySQLPacket(buf, pos)
		if !ok {
			return nil
		}
		pos = np
		col, ok := parseMySQLColumnDef(colPkt)
		if !ok {
			return nil
		}
		cols = append(cols, col)
	}

	if eofPkt, np, ok := readMySQLPacket(buf, pos); ok && len(eofPkt) > 0 && eofPkt[0] == 0xfe && len(eofPkt) < 9 {
		pos = np
	}

	var rows [][]any
	for pos < len(buf) {
		rowPkt, np, ok := readMySQLPacket(buf, pos)
		if !ok || len(rowPkt) == 0 {
			break
		}
		pos = np
		if (rowPkt[0] == 0xfe && len(rowPkt) < 9) || rowPkt[0] == 0xff {
			break
		}
		if rowPkt[0] == 0x00 {
			if row, ok := parseMySQLBinaryRow(rowPkt, cols); ok {
				rows = append(rows, row)
				continue
			}
		}
		row, ok := parseMySQLTextRow(rowPkt, colCount)
		if !ok {
			break
		}
		rows = append(rows, row)
	}

	return &DatabaseResult{
		Columns: cols,
		Rows:    rows,
	}
}

func readCString(buf []byte, start int) (string, int, bool) {
	if start < 0 || start >= len(buf) {
		return "", start, false
	}
	end := bytes.IndexByte(buf[start:], 0)
	if end < 0 {
		return "", len(buf), false
	}
	return string(buf[start : start+end]), start + end + 1, true
}

func parseTrailingAffectedCount(tag string) int64 {
	idx := strings.LastIndexByte(tag, ' ')
	if idx < 0 || idx+1 >= len(tag) {
		return 0
	}
	n, err := strconv.ParseInt(tag[idx+1:], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func readMySQLPacket(buf []byte, pos int) ([]byte, int, bool) {
	if pos+4 > len(buf) {
		return nil, pos, false
	}
	pktLen := int(uint32(buf[pos]) | uint32(buf[pos+1])<<8 | uint32(buf[pos+2])<<16)
	if pktLen < 0 || pos+4+pktLen > len(buf) {
		return nil, pos, false
	}
	return buf[pos+4 : pos+4+pktLen], pos + 4 + pktLen, true
}

func readMySQLLenEncInt(buf []byte, pos int) (uint64, int, bool) {
	if pos >= len(buf) {
		return 0, pos, false
	}
	first := buf[pos]
	switch {
	case first < 0xfb:
		return uint64(first), pos + 1, true
	case first == 0xfc:
		if pos+3 > len(buf) {
			return 0, pos, false
		}
		return uint64(binary.LittleEndian.Uint16(buf[pos+1 : pos+3])), pos + 3, true
	case first == 0xfd:
		if pos+4 > len(buf) {
			return 0, pos, false
		}
		return uint64(buf[pos+1]) | uint64(buf[pos+2])<<8 | uint64(buf[pos+3])<<16, pos + 4, true
	case first == 0xfe:
		if pos+9 > len(buf) {
			return 0, pos, false
		}
		return binary.LittleEndian.Uint64(buf[pos+1 : pos+9]), pos + 9, true
	default:
		return 0, pos + 1, false
	}
}

func readMySQLLenEncString(buf []byte, pos int) (string, int, bool) {
	strLen, nextPos, ok := readMySQLLenEncInt(buf, pos)
	if !ok || nextPos+int(strLen) > len(buf) {
		return "", pos, false
	}
	return string(buf[nextPos : nextPos+int(strLen)]), nextPos + int(strLen), true
}

func parseMySQLColumnDef(pkt []byte) (DatabaseColumn, bool) {
	pos := 0
	for range 4 {
		var ok bool
		_, pos, ok = readMySQLLenEncString(pkt, pos)
		if !ok {
			return DatabaseColumn{}, false
		}
	}
	name, pos, ok := readMySQLLenEncString(pkt, pos)
	if !ok {
		return DatabaseColumn{}, false
	}
	_, pos, ok = readMySQLLenEncString(pkt, pos)
	if !ok {
		return DatabaseColumn{Name: name}, true
	}
	fixedLen, pos, ok := readMySQLLenEncInt(pkt, pos)
	if !ok || fixedLen < 10 || pos+10 > len(pkt) {
		return DatabaseColumn{Name: name}, true
	}
	charset := binary.LittleEndian.Uint16(pkt[pos : pos+2])
	colType := pkt[pos+6]
	flags := binary.LittleEndian.Uint16(pkt[pos+7 : pos+9])
	return DatabaseColumn{
		Name:         name,
		MySQLType:    colType,
		MySQLFlags:   flags,
		MySQLCharset: charset,
	}, true
}

func parseMySQLTextRow(pkt []byte, colCount int) ([]any, bool) {
	row := make([]any, 0, colCount)
	pos := 0
	for range colCount {
		if pos >= len(pkt) {
			return nil, false
		}
		if pkt[pos] == 0xfb {
			row = append(row, nil)
			pos++
			continue
		}
		val, nextPos, ok := readMySQLLenEncString(pkt, pos)
		if !ok {
			return nil, false
		}
		row = append(row, val)
		pos = nextPos
	}
	return row, true
}

func parseMySQLBinaryRow(pkt []byte, cols []DatabaseColumn) ([]any, bool) {
	if len(pkt) == 0 || pkt[0] != 0x00 || len(cols) == 0 {
		return nil, false
	}
	colCount := len(cols)
	nullBitmapLen := (colCount + 7 + 2) / 8
	if 1+nullBitmapLen > len(pkt) {
		return nil, false
	}
	nullBitmap := pkt[1 : 1+nullBitmapLen]
	pos := 1 + nullBitmapLen
	row := make([]any, 0, colCount)
	for i, col := range cols {
		bitPos := i + 2
		if (nullBitmap[bitPos/8] & (1 << (bitPos % 8))) != 0 {
			row = append(row, nil)
			continue
		}
		colType := col.MySQLType
		if colType == 0 {
			colType = mysqlTypeVarString
		}
		unsigned := (col.MySQLFlags & mysqlFlagUnsigned) != 0
		val, nextPos, ok := decodeMySQLBinaryValue(pkt, pos, colType, unsigned)
		if !ok {
			return nil, false
		}
		row = append(row, val)
		pos = nextPos
	}
	return row, true
}

func decodeMySQLBinaryValue(buf []byte, pos int, colType uint8, unsigned bool) (any, int, bool) {
	switch colType {
	case mysqlTypeNull:
		return nil, pos, true
	case mysqlTypeTiny:
		if pos+1 > len(buf) {
			return nil, pos, false
		}
		if unsigned {
			return strconv.FormatUint(uint64(buf[pos]), 10), pos + 1, true
		}
		return strconv.FormatInt(int64(int8(buf[pos])), 10), pos + 1, true
	case mysqlTypeShort, mysqlTypeYear:
		if pos+2 > len(buf) {
			return nil, pos, false
		}
		v := binary.LittleEndian.Uint16(buf[pos : pos+2])
		if unsigned || colType == mysqlTypeYear {
			return strconv.FormatUint(uint64(v), 10), pos + 2, true
		}
		return strconv.FormatInt(int64(int16(v)), 10), pos + 2, true
	case mysqlTypeLong, mysqlTypeInt24:
		if pos+4 > len(buf) {
			return nil, pos, false
		}
		v := binary.LittleEndian.Uint32(buf[pos : pos+4])
		if unsigned {
			return strconv.FormatUint(uint64(v), 10), pos + 4, true
		}
		return strconv.FormatInt(int64(int32(v)), 10), pos + 4, true
	case mysqlTypeLongLong:
		if pos+8 > len(buf) {
			return nil, pos, false
		}
		v := binary.LittleEndian.Uint64(buf[pos : pos+8])
		if unsigned {
			return strconv.FormatUint(v, 10), pos + 8, true
		}
		return strconv.FormatInt(int64(v), 10), pos + 8, true
	case mysqlTypeFloat:
		if pos+4 > len(buf) {
			return nil, pos, false
		}
		f := math.Float32frombits(binary.LittleEndian.Uint32(buf[pos : pos+4]))
		return strconv.FormatFloat(float64(f), 'g', -1, 32), pos + 4, true
	case mysqlTypeDouble:
		if pos+8 > len(buf) {
			return nil, pos, false
		}
		f := math.Float64frombits(binary.LittleEndian.Uint64(buf[pos : pos+8]))
		return strconv.FormatFloat(f, 'g', -1, 64), pos + 8, true
	case mysqlTypeDate, mysqlTypeDatetime, mysqlTypeTimestamp:
		if pos >= len(buf) {
			return nil, pos, false
		}
		n := int(buf[pos])
		pos++
		if pos+n > len(buf) {
			return nil, pos, false
		}
		switch n {
		case 0:
			if colType == mysqlTypeDate {
				return "0000-00-00", pos, true
			}
			return "0000-00-00 00:00:00", pos, true
		case 4:
			year := binary.LittleEndian.Uint16(buf[pos : pos+2])
			return fmt.Sprintf("%04d-%02d-%02d", year, buf[pos+2], buf[pos+3]), pos + 4, true
		case 7:
			year := binary.LittleEndian.Uint16(buf[pos : pos+2])
			return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d",
				year, buf[pos+2], buf[pos+3], buf[pos+4], buf[pos+5], buf[pos+6]), pos + 7, true
		case 11:
			year := binary.LittleEndian.Uint16(buf[pos : pos+2])
			usec := binary.LittleEndian.Uint32(buf[pos+7 : pos+11])
			return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d.%06d",
				year, buf[pos+2], buf[pos+3], buf[pos+4], buf[pos+5], buf[pos+6], usec), pos + 11, true
		default:
			return "", pos + n, false
		}
	case mysqlTypeTime:
		if pos >= len(buf) {
			return nil, pos, false
		}
		n := int(buf[pos])
		pos++
		if pos+n > len(buf) {
			return nil, pos, false
		}
		switch n {
		case 0:
			return "00:00:00", pos, true
		case 8:
			sign := ""
			if buf[pos] == 1 {
				sign = "-"
			}
			days := binary.LittleEndian.Uint32(buf[pos+1 : pos+5])
			hours := days*24 + uint32(buf[pos+5])
			return fmt.Sprintf("%s%02d:%02d:%02d", sign, hours, buf[pos+6], buf[pos+7]), pos + 8, true
		case 12:
			sign := ""
			if buf[pos] == 1 {
				sign = "-"
			}
			days := binary.LittleEndian.Uint32(buf[pos+1 : pos+5])
			hours := days*24 + uint32(buf[pos+5])
			usec := binary.LittleEndian.Uint32(buf[pos+8 : pos+12])
			return fmt.Sprintf("%s%02d:%02d:%02d.%06d", sign, hours, buf[pos+6], buf[pos+7], usec), pos + 12, true
		default:
			return "", pos + n, false
		}
	default:
		s, nextPos, ok := readMySQLLenEncString(buf, pos)
		if !ok {
			return nil, pos, false
		}
		return s, nextPos, true
	}
}

func ParseRedisWireCommandArgs(wire []byte, fallbackCmd, fallbackText string) (string, []string, []string) {
	var tokens []string
	if len(wire) > 0 {
		if wire[0] == '*' {
			tokens = parseRESPArrayStrings(wire)
		} else if line, _, ok := readRESPWireLine(wire, 0); ok && len(line) > 0 {
			tokens = strings.Fields(string(line))
		}
	}
	if len(tokens) == 0 {
		if fallbackText != "" {
			tokens = strings.Fields(fallbackText)
		} else if fallbackCmd != "" {
			tokens = []string{fallbackCmd}
		}
	}
	if len(tokens) == 0 {
		return strings.ToUpper(strings.TrimSpace(fallbackCmd)), nil, nil
	}
	return splitRedisCommandTokens(tokens)
}

func splitRedisCommandTokens(tokens []string) (string, []string, []string) {
	if len(tokens) == 0 {
		return "", nil, nil
	}
	cmd := strings.ToUpper(strings.TrimSpace(tokens[0]))
	args := tokens[1:]
	if len(args) == 0 {
		return cmd, nil, nil
	}

	switch cmd {
	case "MGET", "DEL", "EXISTS", "UNLINK", "SUNION", "SINTER", "SDIFF", "WATCH":
		return cmd, args, nil
	case "MSET", "MSETNX":
		keys := make([]string, 0, (len(args)+1)/2)
		for i := 0; i < len(args); i += 2 {
			keys = append(keys, args[i])
		}
		return cmd, keys, nil
	case "HGET", "HEXISTS", "HINCRBY", "HINCRBYFLOAT", "HSTRLEN":
		if len(args) >= 2 {
			return cmd, []string{args[0]}, []string{args[1]}
		}
		return cmd, []string{args[0]}, nil
	case "HMGET", "HDEL", "SADD", "SREM", "SISMEMBER", "SMISMEMBER", "ZREM":
		if len(args) >= 2 {
			return cmd, []string{args[0]}, args[1:]
		}
		return cmd, []string{args[0]}, nil
	case "HSET", "HMSET", "HSETNX":
		fields := make([]string, 0, len(args)/2)
		for i := 1; i < len(args); i += 2 {
			fields = append(fields, args[i])
		}
		return cmd, []string{args[0]}, fields
	default:
		return cmd, []string{args[0]}, nil
	}
}

func parseRESPArrayStrings(buf []byte) []string {
	line, pos, ok := readRESPWireLine(buf, 0)
	if !ok || len(line) < 2 || line[0] != '*' {
		return nil
	}
	count, err := strconv.Atoi(string(line[1:]))
	if err != nil || count <= 0 || count > 4096 {
		return nil
	}
	out := make([]string, 0, count)
	for range count {
		hdr, nextPos, ok := readRESPWireLine(buf, pos)
		if !ok || len(hdr) < 2 || hdr[0] != '$' {
			return nil
		}
		strLen, err := strconv.Atoi(string(hdr[1:]))
		if err != nil || strLen < 0 || nextPos+strLen+2 > len(buf) {
			return nil
		}
		out = append(out, string(buf[nextPos:nextPos+strLen]))
		pos = nextPos + strLen + 2
	}
	return out
}

func ParseRedisWireReply(buf []byte) *RedisReply {
	reply, _, ok := parseRESPValue(buf, 0, 0)
	if !ok {
		return nil
	}
	return &reply
}

func parseRESPValue(buf []byte, pos, depth int) (RedisReply, int, bool) {
	if depth > 8 || pos >= len(buf) {
		return RedisReply{}, pos, false
	}
	line, nextPos, ok := readRESPWireLine(buf, pos)
	if !ok || len(line) == 0 {
		return RedisReply{}, pos, false
	}

	switch line[0] {
	case '+':
		return RedisReply{Type: "+", Str: string(line[1:])}, nextPos, true
	case '-':
		return RedisReply{Type: "-", Str: string(line[1:])}, nextPos, true
	case ':':
		v, err := strconv.ParseInt(string(line[1:]), 10, 64)
		if err != nil {
			return RedisReply{}, pos, false
		}
		return RedisReply{Type: ":", Int: v}, nextPos, true
	case ',':
		return RedisReply{Type: ",", Str: string(line[1:])}, nextPos, true
	case '_':
		return RedisReply{Type: "$", IsNil: true}, nextPos, true
	case '#':
		if len(line) >= 2 && line[1] == 't' {
			return RedisReply{Type: ":", Int: 1}, nextPos, true
		}
		return RedisReply{Type: ":", Int: 0}, nextPos, true
	case '$', '=', '!':
		bulkLen, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return RedisReply{}, pos, false
		}
		if bulkLen < 0 {
			return RedisReply{Type: "$", IsNil: true}, nextPos, true
		}
		if nextPos+bulkLen+2 > len(buf) {
			return RedisReply{}, pos, false
		}
		data := make([]byte, bulkLen)
		copy(data, buf[nextPos:nextPos+bulkLen])
		if line[0] == '!' {
			return RedisReply{Type: "-", Str: string(data)}, nextPos + bulkLen + 2, true
		}
		return RedisReply{
			Type: "$",
			Bulk: data,
			Str:  string(data),
		}, nextPos + bulkLen + 2, true
	case '*', '~':
		arrLen, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return RedisReply{}, pos, false
		}
		if arrLen < 0 {
			return RedisReply{Type: "*", IsNil: true}, nextPos, true
		}
		if arrLen > 4096 {
			return RedisReply{}, pos, false
		}
		elems := make([]RedisReply, 0, arrLen)
		cur := nextPos
		for range arrLen {
			var elem RedisReply
			var elemOK bool
			elem, cur, elemOK = parseRESPValue(buf, cur, depth+1)
			if !elemOK {
				return RedisReply{}, pos, false
			}
			elems = append(elems, elem)
		}
		typ := "*"
		if line[0] == '~' {
			typ = "~"
		}
		return RedisReply{Type: typ, Elements: elems}, cur, true
	case '%':
		pairCount, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return RedisReply{}, pos, false
		}
		if pairCount < 0 {
			return RedisReply{Type: "%", IsNil: true}, nextPos, true
		}
		if pairCount > 2048 {
			return RedisReply{}, pos, false
		}
		totalElems := pairCount * 2
		elems := make([]RedisReply, 0, totalElems)
		cur := nextPos
		for range totalElems {
			var elem RedisReply
			var elemOK bool
			elem, cur, elemOK = parseRESPValue(buf, cur, depth+1)
			if !elemOK {
				return RedisReply{}, pos, false
			}
			elems = append(elems, elem)
		}
		return RedisReply{Type: "%", Elements: elems}, cur, true
	default:
		return RedisReply{}, pos, false
	}
}

func readRESPWireLine(buf []byte, pos int) ([]byte, int, bool) {
	if pos < 0 || pos >= len(buf) {
		return nil, pos, false
	}
	idx := bytes.Index(buf[pos:], []byte("\r\n"))
	if idx < 0 {
		return nil, pos, false
	}
	return buf[pos : pos+idx], pos + idx + 2, true
}

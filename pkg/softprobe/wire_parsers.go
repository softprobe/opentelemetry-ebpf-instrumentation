// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

func ParsePostgresWireRequestParams(buf []byte) []any {
	pos := 0
	for pos+5 <= len(buf) {
		msgType := buf[pos]
		msgLen := int(binary.BigEndian.Uint32(buf[pos+1 : pos+5]))
		if msgLen < 4 || pos+1+msgLen > len(buf) {
			break
		}
		payload := buf[pos+5 : pos+1+msgLen]
		pos += 1 + msgLen

		if msgType != 'B' {
			continue
		}
		p := 0
		_, p, ok := readCString(payload, p)
		if !ok {
			return nil
		}
		_, p, ok = readCString(payload, p)
		if !ok {
			return nil
		}
		if p+2 > len(payload) {
			return nil
		}
		numFormats := int(binary.BigEndian.Uint16(payload[p : p+2]))
		p += 2 + numFormats*2
		if p+2 > len(payload) {
			return nil
		}
		numParams := int(binary.BigEndian.Uint16(payload[p : p+2]))
		p += 2
		if numParams < 0 || numParams > 4096 {
			return nil
		}
		params := make([]any, 0, numParams)
		for range numParams {
			if p+4 > len(payload) {
				return params
			}
			valLen := int(int32(binary.BigEndian.Uint32(payload[p : p+4])))
			p += 4
			if valLen < 0 {
				params = append(params, nil)
				continue
			}
			if p+valLen > len(payload) {
				return params
			}
			params = append(params, string(payload[p:p+valLen]))
			p += valLen
		}
		return params
	}
	return nil
}

func ParsePostgresWireResponse(buf []byte) *DatabaseResult {
	if len(buf) < 5 {
		return nil
	}
	var res DatabaseResult
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
			if len(payload) < 2 {
				continue
			}
			fieldCount := int(binary.BigEndian.Uint16(payload[:2]))
			p := 2
			cols := make([]DatabaseColumn, 0, min(fieldCount, 512))
			for range fieldCount {
				name, nextP, ok := readCString(payload, p)
				if !ok || nextP+18 > len(payload) {
					break
				}
				typeOID := binary.BigEndian.Uint32(payload[nextP+6 : nextP+10])
				cols = append(cols, DatabaseColumn{
					Name:    name,
					TypeOID: typeOID,
				})
				p = nextP + 18
			}
			res.Columns = cols
			parsedAny = true
		case 'D':
			if len(payload) < 2 {
				continue
			}
			colCount := int(binary.BigEndian.Uint16(payload[:2]))
			p := 2
			row := make([]any, 0, min(colCount, 512))
			for range colCount {
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
				row = append(row, string(payload[p:p+valLen]))
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
		colName, ok := parseMySQLColumnDefName(colPkt)
		if !ok {
			return nil
		}
		cols = append(cols, DatabaseColumn{Name: colName})
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

func parseMySQLColumnDefName(pkt []byte) (string, bool) {
	pos := 0
	for range 4 {
		var ok bool
		_, pos, ok = readMySQLLenEncString(pkt, pos)
		if !ok {
			return "", false
		}
	}
	name, _, ok := readMySQLLenEncString(pkt, pos)
	return name, ok
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

func ParseRedisWireCommandArgs(wire []byte, fallbackCmd, fallbackText string) (string, []string, []string) {
	var tokens []string
	if len(wire) > 0 && wire[0] == '*' {
		tokens = parseRESPArrayStrings(wire)
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
	case '_':
		return RedisReply{Type: "$", IsNil: true}, nextPos, true
	case '#':
		if len(line) >= 2 && line[1] == 't' {
			return RedisReply{Type: ":", Int: 1}, nextPos, true
		}
		return RedisReply{Type: ":", Int: 0}, nextPos, true
	case '$':
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
		return RedisReply{
			Type: "$",
			Bulk: data,
			Str:  string(data),
		}, nextPos + bulkLen + 2, true
	case '*':
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
		return RedisReply{Type: "*", Elements: elems}, cur, true
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

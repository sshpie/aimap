package main

import "testing"

// Cat-02 wave-2 GAP fingerprints, 2026-06-05 — scaffolded from `tome probe` configs.
// real shape passes / FP shape refutes. probeByPath() defined in fingerprints_vectordb_cat02_test.go.

func pr(port, status int, ct, body string) PortResult {
	return PortResult{Host: "203.0.113.9", Port: port, Open: true, StatusCode: status,
		Headers: map[string]string{"Content-Type": ct}, BodySnippet: body}
}

func TestSurrealDB_Match(t *testing.T) {
	p, ok := probeByPath("SurrealDB", "/version")
	if !ok { t.Fatal("SurrealDB /version probe missing") }
	if !matchProbe(p, pr(8000, 200, "text/plain", "surrealdb-2.1.4")) {
		t.Fatal("SurrealDB did not match real /version")
	}
	// FP: generic 8000 service that is NOT surreal
	if matchProbe(p, pr(8000, 200, "application/json", `{"message":"Welcome to FastAPI"}`)) {
		t.Fatal("SurrealDB false-matched a generic 8000 service")
	}
}

func TestInfinity_Match(t *testing.T) {
	p, _ := probeByPath("Infinity", "/databases")
	if !matchProbe(p, pr(23820, 200, "application/json", `{"error_code":0,"databases":["default"]}`)) {
		t.Fatal("Infinity did not match real /databases")
	}
	if matchProbe(p, pr(23820, 200, "application/json", `{"status":"ok"}`)) {
		t.Fatal("Infinity false-matched a body lacking error_code+databases")
	}
}

func TestDatabend_Match(t *testing.T) {
	p, _ := probeByPath("Databend", "/v1/health")
	if !matchProbe(p, pr(8000, 200, "application/json", `{"service":"databend-query","status":"ok"}`)) {
		t.Fatal("Databend did not match")
	}
	if matchProbe(p, pr(8000, 200, "application/json", `{"status":"ok"}`)) {
		t.Fatal("Databend false-matched a generic health body")
	}
}

func TestGreptimeDB_Match(t *testing.T) {
	p, _ := probeByPath("GreptimeDB", "/v1/sql?sql=SELECT+1")
	if !matchProbe(p, pr(4000, 200, "application/json", `{"output":[{"records":{"schema":{"column_schemas":[]},"rows":[[1]]}}]}`)) {
		t.Fatal("GreptimeDB did not match")
	}
	if matchProbe(p, pr(4000, 200, "application/json", `{"error":"bad request"}`)) {
		t.Fatal("GreptimeDB false-matched a non-records body")
	}
}

func TestSolr_Match(t *testing.T) {
	p, _ := probeByPath("Apache Solr", "/solr/admin/info/system")
	if !matchProbe(p, pr(8983, 200, "application/json", `{"lucene":{"solr-spec-version":"9.4.0"}}`)) {
		t.Fatal("Solr did not match")
	}
	if matchProbe(p, pr(8983, 200, "text/html", `<html>some other 8983 service</html>`)) {
		t.Fatal("Solr false-matched")
	}
}

func TestCouchbase_Match(t *testing.T) {
	p, _ := probeByPath("Couchbase", "/pools")
	if !matchProbe(p, pr(8091, 200, "application/json", `{"implementationVersion":"7.6.0","isEnterprise":true}`)) {
		t.Fatal("Couchbase did not match")
	}
	if matchProbe(p, pr(8091, 200, "application/json", `{"pools":[]}`)) {
		t.Fatal("Couchbase false-matched a body lacking implementationVersion")
	}
}

func TestNeo4j_Match(t *testing.T) {
	p, _ := probeByPath("Neo4j", "/")
	if !matchProbe(p, pr(7474, 200, "application/json", `{"bolt_routing":"...","neo4j_version":"5.21.0","neo4j_edition":"community"}`)) {
		t.Fatal("Neo4j did not match")
	}
	if matchProbe(p, pr(7474, 200, "text/html", `<html>nginx</html>`)) {
		t.Fatal("Neo4j false-matched")
	}
}

func TestOceanBase_Match(t *testing.T) {
	p, _ := probeByPath("OceanBase", "/api/v1/status")
	if !matchProbe(p, pr(2886, 200, "application/json", `{"data":{"name":"OceanBase","version":"4.3.0"}}`)) {
		t.Fatal("OceanBase did not match")
	}
	if matchProbe(p, pr(2886, 200, "application/json", `{"data":{"name":"other"}}`)) {
		t.Fatal("OceanBase false-matched")
	}
}

func TestEpsilla_Match(t *testing.T) {
	p, _ := probeByPath("Epsilla", "/api/default/load")
	if !matchProbe(p, pr(8888, 200, "application/json", `{"statusCode":200,"message":"ok","result":[]}`)) {
		t.Fatal("Epsilla did not match")
	}
	if matchProbe(p, pr(8888, 200, "application/json", `{"statusCode":200}`)) {
		t.Fatal("Epsilla false-matched a body lacking message+result")
	}
}

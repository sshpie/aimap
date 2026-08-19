package main

// ML-adjacency rule (Methodology Insight #20).
//
// When a host has a confirmed AI/ML service (from Phase 2 fingerprinting),
// data-tier ports on the SAME host should not be reported as unrelated
// open ports — they're almost certainly part of the same ML pipeline.
//
// The conjunction of (AI service + data-tier port on same host) is a
// stronger signal than either alone. Standalone Postgres on the Internet
// is not an AI finding; Postgres adjacent to MLflow on the same VM is the
// backend datastore for that MLflow tracker.
//
// Reference: published as Insight #20 at
//   https:///methodology/insight-20-aimap-catalog-gaps/

// AdjacencyMatch is emitted for each data-tier port that lives on a host
// with at least one confirmed AI/ML service.
type AdjacencyMatch struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Service  string `json:"service"`  // what the port is, e.g. "PostgreSQL"
	Severity string `json:"severity"` // inherits from the rule + AI-service severity
	Reason   string `json:"reason"`   // why this is ML-adjacent, in one sentence
	BaseURL  string `json:"base_url,omitempty"`
	// Adjacents is the set of AI services on the same host that triggered
	// the adjacency, by service name.
	Adjacents []string `json:"adjacent_to"`
}

// dataTierPort describes a port worth flagging as ML-adjacent when an AI
// service is confirmed on the same host.
type dataTierPort struct {
	Port     int
	Service  string
	Severity string
	Reason   string
}

// dataTierCatalog: the ports the insight specifically called out, plus a
// short rationale for each. Severity here is the *adjacency-elevated*
// severity — a standalone Postgres scan would not earn HIGH, but
// "Postgres directly Internet-exposed alongside an unauth MLflow tracker"
// is HIGH because compromise of one side gives the attacker the other.
var dataTierCatalog = []dataTierPort{
	{
		Port: 5432, Service: "PostgreSQL", Severity: "high",
		Reason: "Internet-exposed backend datastore adjacent to a confirmed AI/ML service. Likely the MLflow/Langfuse/Phoenix backing store.",
	},
	{
		Port: 6379, Service: "Redis", Severity: "high",
		Reason: "Internet-exposed cache adjacent to a confirmed AI/ML service. Likely the inference-cache or session-store for the AI stack.",
	},
	{
		Port: 9000, Service: "MinIO (S3-compatible)", Severity: "high",
		Reason: "Internet-exposed object store adjacent to a confirmed AI/ML service. Likely the local artifact store or RAG document corpus.",
	},
	{
		Port: 9001, Service: "MinIO console", Severity: "medium",
		Reason: "MinIO admin console adjacent to a confirmed AI/ML service. Pairs with the S3 API on 9000.",
	},
	{
		Port: 9092, Service: "Kafka", Severity: "medium",
		Reason: "Kafka broker adjacent to a confirmed AI/ML service. Likely streaming inference, event-driven RAG, or telemetry sink.",
	},
	{
		Port: 5672, Service: "RabbitMQ AMQP", Severity: "medium",
		Reason: "RabbitMQ broker adjacent to a confirmed AI/ML service. Likely inference queueing.",
	},
	{
		Port: 15672, Service: "RabbitMQ management", Severity: "medium",
		Reason: "RabbitMQ management UI adjacent to a confirmed AI/ML service.",
	},
	{
		Port: 1025, Service: "MailHog SMTP", Severity: "low",
		Reason: "MailHog SMTP sink adjacent to a confirmed AI/ML service. Inference-pipeline notification sink.",
	},
	{
		Port: 8025, Service: "MailHog web", Severity: "low",
		Reason: "MailHog web UI adjacent to a confirmed AI/ML service. Inference-pipeline notification sink.",
	},
}

// buildAdjacencies derives ML-adjacency findings for hosts that have at
// least one confirmed AI/ML service. Returns one AdjacencyMatch per
// (host, port) tuple where the port matches the data-tier catalog and is
// not already covered by an explicit ServiceMatch on the same port.
func buildAdjacencies(services []ServiceMatch, openPorts []PortResult) []AdjacencyMatch {
	if len(services) == 0 {
		return nil
	}

	// Index AI-service hosts → list of service names (for the Adjacents
	// field). A host appears only if it has ≥1 confirmed AI service.
	aiHosts := map[string][]string{}
	servicedPort := map[string]bool{} // "host:port" → already a ServiceMatch
	for _, s := range services {
		aiHosts[s.Host] = append(aiHosts[s.Host], s.Service)
		servicedPort[hostPortKey(s.Host, s.Port)] = true
	}

	// Index data-tier catalog by port for O(1) lookup.
	catalog := map[int]dataTierPort{}
	for _, dt := range dataTierCatalog {
		catalog[dt.Port] = dt
	}

	var out []AdjacencyMatch
	for _, op := range openPorts {
		if !op.Open {
			continue
		}
		// Skip if the port is already in the ServiceMatch set — it's been
		// classified, not adjacent.
		if servicedPort[hostPortKey(op.Host, op.Port)] {
			continue
		}
		dt, ok := catalog[op.Port]
		if !ok {
			continue
		}
		adjacents := aiHosts[op.Host]
		if len(adjacents) == 0 {
			continue
		}
		out = append(out, AdjacencyMatch{
			Host:      op.Host,
			Port:      op.Port,
			Service:   dt.Service,
			Severity:  dt.Severity,
			Reason:    dt.Reason,
			BaseURL:   "", // data-tier ports aren't HTTP; no URL
			Adjacents: adjacents,
		})
	}
	return out
}

func hostPortKey(host string, port int) string {
	// fmt.Sprintf would work; this avoids the import dependency and is
	// just as fast for the small map sizes involved.
	return host + ":" + intToStr(port)
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

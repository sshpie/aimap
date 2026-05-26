package main

import (
	"testing"
)

// Tests for GraphQL helper functions in enumerators.go.

// ── gqlFieldNames ─────────────────────────────────────────────────────────────

func TestGqlFieldNames_Canonical(t *testing.T) {
	// Simulates the __schema.queryType.fields response shape returned by
	// GraphQL introspection against a live Apollo endpoint.
	m := map[string]interface{}{
		"data": map[string]interface{}{
			"__schema": map[string]interface{}{
				"queryType": map[string]interface{}{
					"fields": []interface{}{
						map[string]interface{}{"name": "allUsers"},
						map[string]interface{}{"name": "getCustomUsersCsv"},
					},
				},
			},
		},
	}

	got := gqlFieldNames(m, "data", "__schema", "queryType", "fields")
	want := []string{"allUsers", "getCustomUsersCsv"}

	if len(got) != len(want) {
		t.Fatalf("expected %d fields, got %d: %v", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d: want %q, got %q", i, w, got[i])
		}
	}
}

func TestGqlFieldNames_MissingPath_ReturnsNil(t *testing.T) {
	// A response missing the expected nested key must return nil, not panic.
	m := map[string]interface{}{
		"data": map[string]interface{}{
			"__schema": map[string]interface{}{
				// "queryType" key absent
			},
		},
	}

	got := gqlFieldNames(m, "data", "__schema", "queryType", "fields")
	if got != nil {
		t.Errorf("expected nil for missing path, got %v", got)
	}
}

func TestGqlFieldNames_EmptyFieldsArray(t *testing.T) {
	m := map[string]interface{}{
		"data": map[string]interface{}{
			"__schema": map[string]interface{}{
				"queryType": map[string]interface{}{
					"fields": []interface{}{},
				},
			},
		},
	}

	got := gqlFieldNames(m, "data", "__schema", "queryType", "fields")
	// An empty array is valid; the result should be nil (no names appended).
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestGqlFieldNames_SkipsEmptyName(t *testing.T) {
	// Objects with an empty "name" field must be excluded.
	m := map[string]interface{}{
		"data": map[string]interface{}{
			"__schema": map[string]interface{}{
				"queryType": map[string]interface{}{
					"fields": []interface{}{
						map[string]interface{}{"name": "validField"},
						map[string]interface{}{"name": ""},
						map[string]interface{}{"name": "anotherField"},
					},
				},
			},
		},
	}

	got := gqlFieldNames(m, "data", "__schema", "queryType", "fields")
	want := []string{"validField", "anotherField"}

	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d: want %q, got %q", i, w, got[i])
		}
	}
}

func TestGqlFieldNames_MutationType(t *testing.T) {
	// Same path logic applies to mutationType fields.
	m := map[string]interface{}{
		"data": map[string]interface{}{
			"__schema": map[string]interface{}{
				"mutationType": map[string]interface{}{
					"fields": []interface{}{
						map[string]interface{}{"name": "createUser"},
						map[string]interface{}{"name": "deleteUser"},
						map[string]interface{}{"name": "updateUserRole"},
					},
				},
			},
		},
	}

	got := gqlFieldNames(m, "data", "__schema", "mutationType", "fields")
	want := []string{"createUser", "deleteUser", "updateUserRole"}

	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d: want %q, got %q", i, w, got[i])
		}
	}
}

func TestGqlFieldNames_IntermediateNotMap_ReturnsNil(t *testing.T) {
	// If a node along the path is a scalar, not a map, return nil gracefully.
	m := map[string]interface{}{
		"data": "unexpected_string_not_a_map",
	}

	got := gqlFieldNames(m, "data", "__schema", "queryType", "fields")
	if got != nil {
		t.Errorf("expected nil when intermediate node is not a map, got %v", got)
	}
}

func TestGqlFieldNames_TerminalNotArray_ReturnsNil(t *testing.T) {
	// If the terminal node is not an array, return nil.
	m := map[string]interface{}{
		"data": map[string]interface{}{
			"__schema": map[string]interface{}{
				"queryType": map[string]interface{}{
					"fields": "not_an_array",
				},
			},
		},
	}

	got := gqlFieldNames(m, "data", "__schema", "queryType", "fields")
	if got != nil {
		t.Errorf("expected nil when terminal value is not an array, got %v", got)
	}
}

// ── gqlFieldNamesFlat ─────────────────────────────────────────────────────────

func TestGqlFieldNamesFlat_SameAsGqlFieldNames(t *testing.T) {
	// gqlFieldNamesFlat is an alias — verify identical output.
	m := map[string]interface{}{
		"data": map[string]interface{}{
			"__type": map[string]interface{}{
				"fields": []interface{}{
					map[string]interface{}{"name": "id"},
					map[string]interface{}{"name": "email"},
				},
			},
		},
	}

	flat := gqlFieldNamesFlat(m, "data", "__type", "fields")
	normal := gqlFieldNames(m, "data", "__type", "fields")

	if len(flat) != len(normal) {
		t.Fatalf("flat=%v normal=%v — lengths differ", flat, normal)
	}
	for i := range flat {
		if flat[i] != normal[i] {
			t.Errorf("index %d: flat=%q normal=%q", i, flat[i], normal[i])
		}
	}
}

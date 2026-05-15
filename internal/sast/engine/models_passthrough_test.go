package engine

import (
	"testing"
)

// TestLoadBuiltinModels_PassthroughsPopulated: kind=passthrough entries from
// the embedded model packs land in the Passthroughs map keyed by
// receiver+"."+method (and by bare method for empty-receiver entries).
func TestLoadBuiltinModels_PassthroughsPopulated(t *testing.T) {
	ms, err := LoadBuiltinModels()
	if err != nil {
		t.Fatalf("LoadBuiltinModels: %v", err)
	}
	if ms.Passthroughs == nil {
		t.Fatal("Passthroughs map is nil")
	}
	if len(ms.Passthroughs) == 0 {
		t.Fatal("Passthroughs map is empty — expected anchor entries from java/js/csharp templating + strings packs")
	}

	mustHave := []string{
		"java.lang.String.format",
		"String.format",
		"Array.prototype.join",
		"join", // bare-method fallback
		"System.String.Concat",
		"System.String.Format",
		"string.Concat",
		"string.Format",
	}
	for _, key := range mustHave {
		if _, ok := ms.Passthroughs[key]; !ok {
			t.Errorf("Passthroughs missing expected key %q", key)
		}
	}
}

// TestIsPassthrough_Match: known passthrough FQN returns true + the model
// entries; unknown FQN returns false + nil.
func TestIsPassthrough_Match(t *testing.T) {
	ms, err := LoadBuiltinModels()
	if err != nil {
		t.Fatalf("LoadBuiltinModels: %v", err)
	}

	ok, models := ms.IsPassthrough("java.lang.String.format")
	if !ok {
		t.Fatal("IsPassthrough(java.lang.String.format) = false, want true")
	}
	if len(models) == 0 {
		t.Fatal("IsPassthrough returned empty models slice")
	}
	if models[0].Kind != ModelPassthrough {
		t.Errorf("model kind = %q, want %q", models[0].Kind, ModelPassthrough)
	}

	ok, models = ms.IsPassthrough("com.example.NotAPassthrough.foo")
	if ok {
		t.Errorf("IsPassthrough(unknown FQN) = true, want false")
	}
	if models != nil {
		t.Errorf("IsPassthrough(unknown FQN) returned non-nil models: %v", models)
	}
}

// TestPassthroughModels_NotMixedIntoOtherCategories: passthrough entries must
// not leak into Sources / Sinks / Sanitizers, otherwise we'd double-classify
// calls (e.g. emit a sink finding for String.format).
func TestPassthroughModels_NotMixedIntoOtherCategories(t *testing.T) {
	ms, err := LoadBuiltinModels()
	if err != nil {
		t.Fatalf("LoadBuiltinModels: %v", err)
	}
	passthroughKeys := []string{
		"java.lang.String.format",
		"Array.prototype.join",
		"System.String.Concat",
	}
	for _, key := range passthroughKeys {
		if _, ok := ms.Sources[key]; ok {
			t.Errorf("passthrough key %q leaked into Sources", key)
		}
		if _, ok := ms.Sinks[key]; ok {
			t.Errorf("passthrough key %q leaked into Sinks", key)
		}
		if _, ok := ms.Sanitizers[key]; ok {
			t.Errorf("passthrough key %q leaked into Sanitizers", key)
		}
	}
}

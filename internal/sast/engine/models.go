package engine

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed models/*.json
var modelsFS embed.FS

// ModelKind distinguishes the four kinds of taint-model entries.
type ModelKind string

const (
	ModelSource     ModelKind = "source"
	ModelSink       ModelKind = "sink"
	ModelSanitizer  ModelKind = "sanitizer"
	ModelPassthrough ModelKind = "passthrough"
)

// TaintModel is a single source/sink/sanitizer/passthrough declaration
// loaded from the embedded model pack.
type TaintModel struct {
	Kind            ModelKind `json:"kind"`
	ReceiverFQN     string    `json:"receiver_fqn,omitempty"`
	MethodName      string    `json:"method,omitempty"`
	TaintKind       string    `json:"taint_kind,omitempty"`
	VulnClass       string    `json:"vuln_class,omitempty"`
	ForClasses      []string  `json:"for_classes,omitempty"`
	ArgIndex        *int      `json:"arg_index,omitempty"`
	ArgCountExact   *int      `json:"arg_count_exact,omitempty"` // sink only: match only when call has exactly this many args
	AppliesTo       string    `json:"applies_to,omitempty"`
	AnnotationFQN   string    `json:"annotation_fqn,omitempty"`
}

// ModelPack is a collection of taint models for a specific language/framework.
type ModelPack struct {
	Language  string       `json:"language"`
	Framework string       `json:"framework"`
	Models    []TaintModel `json:"models"`
}

// ModelSet is the compiled set of models the taint engine uses at analysis
// time. It provides fast lookups by (receiverFQN + method) for sinks, sources,
// and sanitizers.
type ModelSet struct {
	Sources     map[string][]TaintModel // key = receiverFQN+"."+method or annotation FQN
	Sinks       map[string][]TaintModel
	Sanitizers  map[string][]TaintModel
}

// LoadBuiltinModels loads and compiles the embedded model packs.
func LoadBuiltinModels() (*ModelSet, error) {
	ms := &ModelSet{
		Sources:    map[string][]TaintModel{},
		Sinks:      map[string][]TaintModel{},
		Sanitizers: map[string][]TaintModel{},
	}
	err := fs.WalkDir(modelsFS, "models", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		data, rErr := fs.ReadFile(modelsFS, path)
		if rErr != nil {
			return fmt.Errorf("read %s: %w", path, rErr)
		}
		var pack ModelPack
		if jErr := json.Unmarshal(data, &pack); jErr != nil {
			return fmt.Errorf("parse %s: %w", path, jErr)
		}
		for _, m := range pack.Models {
			key := m.ReceiverFQN + "." + m.MethodName
			if m.AnnotationFQN != "" {
				key = m.AnnotationFQN
			}
			switch m.Kind {
			case ModelSource:
				ms.Sources[key] = append(ms.Sources[key], m)
			case ModelSink:
				ms.Sinks[key] = append(ms.Sinks[key], m)
			case ModelSanitizer:
				ms.Sanitizers[key] = append(ms.Sanitizers[key], m)
			}
			// For bare-function models (empty receiver), also register by
			// just the method name so the taint engine finds them when
			// calleeFQN is the method name alone (common in JS).
			if m.ReceiverFQN == "" && m.MethodName != "" {
				bareKey := m.MethodName
				switch m.Kind {
				case ModelSource:
					ms.Sources[bareKey] = append(ms.Sources[bareKey], m)
				case ModelSink:
					ms.Sinks[bareKey] = append(ms.Sinks[bareKey], m)
				case ModelSanitizer:
					ms.Sanitizers[bareKey] = append(ms.Sanitizers[bareKey], m)
				}
			}
		}
		return nil
	})
	return ms, err
}

// IsSource returns true + the taint kind if the given calleeFQN is a known
// taint source.
func (ms *ModelSet) IsSource(calleeFQN string) (bool, string) {
	if models, ok := ms.Sources[calleeFQN]; ok && len(models) > 0 {
		return true, models[0].TaintKind
	}
	return false, ""
}

// IsSink returns true + the vuln class + the matching models if the given
// calleeFQN is a known taint sink. The caller uses the models to check
// constraints like ArgCountExact.
func (ms *ModelSet) IsSink(calleeFQN string) (bool, string, []TaintModel) {
	if models, ok := ms.Sinks[calleeFQN]; ok && len(models) > 0 {
		return true, models[0].VulnClass, models
	}
	return false, "", nil
}

// IsSanitizer returns true if the given calleeFQN is a sanitizer for the
// specified vulnerability class.
func (ms *ModelSet) IsSanitizer(calleeFQN, vulnClass string) bool {
	if models, ok := ms.Sanitizers[calleeFQN]; ok {
		for _, m := range models {
			for _, c := range m.ForClasses {
				if c == vulnClass {
					return true
				}
			}
		}
	}
	return false
}

package crypto

import (
	"encoding/json"
	"sort"
)

// Canonicalize produces a canonical JSON byte representation:
// sorted keys at every level, no whitespace, UTF-8.
func Canonicalize(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	sorted := sortKeys(raw)
	return json.Marshal(sorted)
}

func sortKeys(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(orderedMap, 0, len(val))
		for _, k := range keys {
			ordered = append(ordered, mapEntry{Key: k, Value: sortKeys(val[k])})
		}
		return ordered
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = sortKeys(item)
		}
		return result
	default:
		return v
	}
}

// orderedMap preserves key order during JSON marshaling.
type orderedMap []mapEntry

type mapEntry struct {
	Key   string
	Value interface{}
}

func (m orderedMap) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, entry := range m {
		if i > 0 {
			buf = append(buf, ',')
		}
		key, _ := json.Marshal(entry.Key)
		val, err := json.Marshal(entry.Value)
		if err != nil {
			return nil, err
		}
		buf = append(buf, key...)
		buf = append(buf, ':')
		buf = append(buf, val...)
	}
	buf = append(buf, '}')
	return buf, nil
}

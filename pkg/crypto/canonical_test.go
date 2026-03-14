package crypto

import (
	"encoding/json"
	"testing"
)

func TestCanonicalize_GoldenVectors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "sort top-level keys",
			input: `{"b":2,"a":1}`,
			want:  `{"a":1,"b":2}`,
		},
		{
			name:  "sort nested keys",
			input: `{"z":{"b":2,"a":1}}`,
			want:  `{"z":{"a":1,"b":2}}`,
		},
		{
			name:  "preserve UTF-8",
			input: `{"a":"café"}`,
			want:  `{"a":"café"}`,
		},
		{
			name:  "empty object",
			input: `{}`,
			want:  `{}`,
		},
		{
			name:  "arrays NOT sorted",
			input: `{"a":[3,1,2]}`,
			want:  `{"a":[3,1,2]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v interface{}
			if err := json.Unmarshal([]byte(tt.input), &v); err != nil {
				t.Fatalf("unmarshal input: %v", err)
			}
			got, err := Canonicalize(v)
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %s\nwant %s", string(got), tt.want)
			}
		})
	}
}

func TestCanonicalize_DeeplyNested(t *testing.T) {
	input := `{"c":{"z":1,"a":{"y":2,"x":3}},"b":4,"a":5}`
	want := `{"a":5,"b":4,"c":{"a":{"x":3,"y":2},"z":1}}`

	var v interface{}
	if err := json.Unmarshal([]byte(input), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := Canonicalize(v)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", string(got), want)
	}
}

func TestCanonicalize_Struct(t *testing.T) {
	type inner struct {
		Z int    `json:"z"`
		A string `json:"a"`
	}
	type outer struct {
		B inner `json:"b"`
		A int   `json:"a"`
	}
	v := outer{B: inner{Z: 1, A: "hello"}, A: 2}
	got, err := Canonicalize(v)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"a":2,"b":{"a":"hello","z":1}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", string(got), want)
	}
}

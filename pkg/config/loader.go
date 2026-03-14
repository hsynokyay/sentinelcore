package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// Load fills a config struct from environment variables.
// Env var names: SENTINELCORE_ + upper(field name with _ separators)
// Example: DBHost -> SENTINELCORE_DB_HOST
// Supports string, int, bool, []string (comma-separated).
// Use struct tag `required:"true"` to mark mandatory fields.
// Use struct tag `default:"value"` to provide a default.
func Load(cfg interface{}) error {
	v := reflect.ValueOf(cfg)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("config.Load: expected pointer to struct, got %T", cfg)
	}
	v = v.Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fv := v.Field(i)

		if !fv.CanSet() {
			continue
		}

		envKey := "SENTINELCORE_" + camelToUpperSnake(field.Name)
		val, found := os.LookupEnv(envKey)
		if !found {
			if def, ok := field.Tag.Lookup("default"); ok {
				val = def
				found = true
			}
		}

		if !found {
			if field.Tag.Get("required") == "true" {
				return fmt.Errorf("config.Load: required env var %s not set", envKey)
			}
			continue
		}

		if err := setField(fv, val); err != nil {
			return fmt.Errorf("config.Load: field %s: %w", field.Name, err)
		}
	}
	return nil
}

func camelToUpperSnake(name string) string {
	var result []rune
	for i, r := range name {
		if unicode.IsUpper(r) && i > 0 {
			prev := rune(name[i-1])
			if unicode.IsLower(prev) || (i+1 < len(name) && unicode.IsLower(rune(name[i+1]))) {
				result = append(result, '_')
			}
		}
		result = append(result, unicode.ToUpper(r))
	}
	return string(result)
}

func setField(fv reflect.Value, val string) error {
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(val)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}
		fv.SetInt(n)
	case reflect.Bool:
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		fv.SetBool(b)
	case reflect.Slice:
		if fv.Type().Elem().Kind() == reflect.String {
			parts := strings.Split(val, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			fv.Set(reflect.ValueOf(parts))
		} else {
			return fmt.Errorf("unsupported slice type: %v", fv.Type().Elem().Kind())
		}
	default:
		return fmt.Errorf("unsupported field type: %v", fv.Kind())
	}
	return nil
}

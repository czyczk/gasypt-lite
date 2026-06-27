package gasypt

import (
	"fmt"
	"reflect"
	"strings"
)

const tagKey = "gasypt"
const tagValueEncrypted = "encrypted"
const tagValueAlgorithm = "algorithm"

// DecryptFields walks the fields of v (which must be a pointer to a struct),
// finds those tagged `gasypt:"encrypted"`, and replaces their ENC(…) values
// with the decrypted plaintext. Fields without ENC(…) wrapping are silently
// skipped. Per-field algorithm tags are respected.
//
//	cfg := &Config{Password: gasypt.WrapEnc(ct)}
//	gasypt.DecryptFields(cfg, "master-password")
func DecryptFields(v interface{}, password string) error {
	return decryptFieldsImpl(v, password, false, PBEWithHMACSHA512AndAES_256)
}

// DecryptFieldsWith is like DecryptFields but uses the given algorithm for all
// tagged fields, ignoring any per-field algorithm tags.
func DecryptFieldsWith(v interface{}, algo Algorithm, password string) error {
	return decryptFieldsImpl(v, password, true, algo)
}

func decryptFieldsImpl(v interface{}, password string, overrideAlgo bool, runtimeAlgo Algorithm) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("gasypt: DecryptFields requires a pointer to struct")
	}

	elem := rv.Elem()
	t := elem.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get(tagKey)
		if tag == "" || !strings.Contains(tag, tagValueEncrypted) {
			continue
		}

		algo := runtimeAlgo
		if !overrideAlgo {
			algo = parseTagAlgorithm(tag, PBEWithHMACSHA512AndAES_256)
		}

		fv := elem.Field(i)

		switch fv.Kind() {
		case reflect.String:
			val := fv.String()
			if !IsEncValue(val) {
				continue
			}
			decrypted, err := DecryptEncWith(algo, val, password)
			if err != nil {
				return fmt.Errorf("gasypt: field %q: %w", field.Name, err)
			}
			fv.SetString(decrypted)

		case reflect.Ptr:
			if fv.IsNil() {
				continue
			}
			if fv.Elem().Kind() == reflect.String {
				val := fv.Elem().String()
				if !IsEncValue(val) {
					continue
				}
				decrypted, err := DecryptEncWith(algo, val, password)
				if err != nil {
					return fmt.Errorf("gasypt: field %q: %w", field.Name, err)
				}
				fv.Elem().SetString(decrypted)
			}
		}
	}

	return nil
}

// ClearSensitiveFields walks the fields of v (which must be a pointer to a
// struct) and sets all fields tagged `gasypt:"encrypted"` to the empty string.
// Use this after you are done with decrypted values to minimise their lifetime
// in memory.
func ClearSensitiveFields(v interface{}) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.Elem().Kind() != reflect.Struct {
		return
	}

	elem := rv.Elem()
	t := elem.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get(tagKey)
		if tag == "" || !strings.Contains(tag, tagValueEncrypted) {
			continue
		}

		fv := elem.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString("")
		case reflect.Ptr:
			if !fv.IsNil() && fv.Elem().Kind() == reflect.String {
				fv.Elem().SetString("")
			}
		}
	}
}

func parseTagAlgorithm(tag string, defaultAlgo Algorithm) Algorithm {
	parts := strings.Split(tag, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, tagValueAlgorithm+"=") {
			name := strings.TrimPrefix(part, tagValueAlgorithm+"=")
			name = strings.TrimSpace(name)
			if algo, ok := ParseAlgorithm(name); ok {
				return algo
			}
		}
	}
	return defaultAlgo
}

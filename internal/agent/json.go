package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Object = map[string]any

func obj(v any) Object {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return Object{}
}
func str(v any) string { s, _ := v.(string); return s }
func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
func list(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}
func clone(v Object) Object {
	r := Object{}
	for k, x := range v {
		r[k] = x
	}
	return r
}
func JSON(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func readJSON(path string) (Object, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var v Object
	e = json.Unmarshal(b, &v)
	return v, e
}
func Atomic(path string, v any) error { return AtomicText(path, append(JSON(v), '\n')) }
func AtomicText(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path))
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func now() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00") }
func moment(v any) float64 {
	t, _ := time.Parse(time.RFC3339Nano, str(v))
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}
func token() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func required(v Object, fields ...string) error {
	for _, f := range fields {
		if v[f] == nil {
			return fmt.Errorf("missing %s", f)
		}
	}
	return nil
}

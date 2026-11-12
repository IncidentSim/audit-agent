package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPythonCompactCompatibility(t *testing.T) {
	files, e := filepath.Glob("testdata/compact/*.json")
	if e != nil || len(files) < 20 {
		t.Fatal("missing migration fixtures")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, e := os.ReadFile(f)
			if e != nil {
				t.Fatal(e)
			}
			var fixture struct {
				Events   []Object
				Manifest Object
				Options  Object
				Packet   Object
				Refs     Object
			}
			if e = json.Unmarshal(b, &fixture); e != nil {
				t.Fatal(e)
			}
			el, xl := 24, 12
			if v, ok := fixture.Options["effects_limit"]; ok {
				el = int(num(v))
			}
			if v, ok := fixture.Options["exec_limit"]; ok {
				xl = int(num(v))
			}
			packet, refs, _, e := BuildPacket(fixture.Events, fixture.Manifest, el, xl)
			if e != nil {
				t.Fatal(e)
			}
			var normalized Object
			json.Unmarshal(JSON(packet), &normalized)
			if !reflect.DeepEqual(normalized, fixture.Packet) {
				t.Errorf("packet differs\ngot: %s\nwant: %s", JSON(normalized), JSON(fixture.Packet))
			}
			normalized = nil
			json.Unmarshal(JSON(refs), &normalized)
			if !reflect.DeepEqual(normalized, fixture.Refs) {
				t.Errorf("refs differ: %s / %s", JSON(refs), JSON(fixture.Refs))
			}
		})
	}
}

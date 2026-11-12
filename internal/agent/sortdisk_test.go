package agent

import (
	"fmt"
	"strconv"
	"testing"
)

func TestDiskSortStableAcrossMultipleMergePasses(t *testing.T) {
	sorter := &diskSort{dir: t.TempDir()}
	const count = 600
	for i := 0; i < count; i++ {
		if err := sorter.Add(fmt.Sprint(i%7), []byte(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
		if i%10 == 9 {
			if err := sorter.flush(); err != nil {
				t.Fatal(err)
			}
		}
	}
	lastKey, previous, seen := "", -1, 0
	if err := sorter.Finish(func(row sortRecord) error {
		n, err := strconv.Atoi(string(row.data))
		if err != nil {
			return err
		}
		if row.key < lastKey || (row.key == lastKey && n <= previous) {
			t.Fatalf("unstable merge: %s/%d after %s/%d", row.key, n, lastKey, previous)
		}
		lastKey, previous = row.key, n
		seen++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != count {
		t.Fatalf("sort lost rows: %d", seen)
	}
}

func TestPublishExportDeduplicatesAcrossRunsAndOrdersChronologically(t *testing.T) {
	dir := t.TempDir()
	sorter := &diskSort{dir: dir}
	add := func(id, timestamp, value string, replace bool) {
		t.Helper()
		priority := byte(0)
		if replace {
			priority = 1
		}
		if err := sorter.Add(id, append([]byte{priority}, JSON(Object{"event_id": id, "timestamp": timestamp, "value": value})...)); err != nil {
			t.Fatal(err)
		}
		if err := sorter.flush(); err != nil {
			t.Fatal(err)
		}
	}
	add("b", "2026-01-01T00:00:01Z", "first JSONL", false)
	add("b", "2026-01-01T00:00:01Z", "second JSONL", false)
	add("a", "2026-01-01T00:00:02Z", "damaged", false)
	add("a", "2026-01-01T00:00:02Z", "raw", true)
	add("c", "1969-01-01T00:00:00Z", "old", false)
	output := dir + "/actions.jsonl"
	summary, err := publishExport(sorter, output, dir)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ReadEvents(output)
	if err != nil || len(rows) != 3 || summary.Count != 3 {
		t.Fatalf("export: %v %v", rows, err)
	}
	if rows[0]["event_id"] != "c" || rows[1]["value"] != "first JSONL" || rows[2]["value"] != "raw" {
		t.Fatal(rows)
	}
}

package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// Raw audit logs commonly have no EOE records. Sort records by event before
// parsing, so even interleaved events crossing rotations need only one event
// in memory. Exclude other recording windows before allocating parsed fields.
func rawExportKey(line string, window Object) (string, bool, error) {
	m := auditStamp.FindStringSubmatch(line)
	if m == nil {
		if strings.TrimSpace(line) == "" {
			return "", false, nil
		}
		return "", false, errors.New("audit record has no event timestamp")
	}
	seconds, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return "", false, err
	}
	millis, _ := strconv.Atoi((m[2] + "000")[:3])
	serial, err := strconv.ParseInt(m[3], 10, 64)
	if err != nil {
		return "", false, err
	}
	if window != nil {
		start, end := obj(window["start_boundary"]), obj(window["stop_boundary"])
		stamp := float64(seconds) + float64(millis)/1000
		if len(start) == 0 || float64(serial) <= num(start["serial"]) || stamp < moment(start["timestamp"]) {
			return "", false, nil
		}
		if len(end) != 0 && (float64(serial) >= num(end["serial"]) || stamp > moment(end["timestamp"])) {
			return "", false, nil
		}
	}
	return fmt.Sprintf("%020d:%03d:%020d", seconds, millis, serial), true, nil
}

type exportSummary struct {
	Count       int
	First, Last any
}

func publishExport(candidates *diskSort, output, temporary string) (summary exportSummary, err error) {
	ordered := &diskSort{dir: temporary}
	var selected []byte
	previous := ""
	selectEvent := func() error {
		if selected == nil {
			return nil
		}
		var event struct {
			Timestamp any    `json:"timestamp"`
			ID        string `json:"event_id"`
		}
		if err := json.Unmarshal(selected, &event); err != nil {
			return err
		}
		bits := math.Float64bits(moment(event.Timestamp))
		if bits>>63 != 0 {
			bits = ^bits
		} else {
			bits ^= uint64(1) << 63
		}
		return ordered.Add(fmt.Sprintf("%016x:%s", bits, event.ID), selected)
	}
	err = candidates.Finish(func(row sortRecord) error {
		if row.key != previous {
			if err := selectEvent(); err != nil {
				return err
			}
			previous, selected = row.key, nil
		}
		// First JSONL copy wins; a recovered raw event replaces it. Stable
		// merging preserves that rule even when copies are in separate runs.
		if selected == nil || row.data[0] == 1 {
			selected = row.data[1:]
		}
		return nil
	})
	if err != nil {
		return summary, err
	}
	if err := selectEvent(); err != nil {
		return summary, err
	}
	err = atomicWrite(output, func(file io.Writer) error {
		writer := bufio.NewWriter(file)
		if err := ordered.Finish(func(row sortRecord) error {
			if _, err := writer.Write(row.data); err != nil {
				return err
			}
			if err := writer.WriteByte('\n'); err != nil {
				return err
			}
			var event struct {
				Timestamp any `json:"timestamp"`
			}
			if err := json.Unmarshal(row.data, &event); err != nil {
				return err
			}
			if summary.Count == 0 {
				summary.First = event.Timestamp
			}
			summary.Count++
			summary.Last = event.Timestamp
			return nil
		}); err != nil {
			return err
		}
		return writer.Flush()
	})
	return summary, err
}

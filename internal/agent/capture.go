package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Store struct {
	Root, Boot string
	Write      func(Object, string) error
}

func ValidSession(s string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`).MatchString(s) {
		return errors.New("session ID must be 1-96 ASCII letters, digits, dots, underscores or hyphens")
	}
	return nil
}
func (s *Store) directory(id string) string { return filepath.Join(s.Root, "sessions", id) }
func (s *Store) Current() (Object, error) {
	v, e := readJSON(filepath.Join(s.Root, "capture.json"))
	if os.IsNotExist(e) {
		return nil, nil
	}
	return v, e
}
func (s *Store) Get(id string) (Object, error) {
	v, e := s.Current()
	if e != nil {
		return nil, e
	}
	if id == "" {
		if v == nil {
			return nil, errors.New("no recording session; call incident-audit start first")
		}
		return v, nil
	}
	if e = ValidSession(id); e != nil {
		return nil, e
	}
	if v != nil && v["session_id"] == id {
		return v, nil
	}
	return readJSON(filepath.Join(s.directory(id), "session.json"))
}
func (s *Store) save(v Object) error {
	if e := Atomic(filepath.Join(s.Root, "capture.json"), v); e != nil {
		return e
	}
	return Atomic(filepath.Join(s.directory(str(v["session_id"])), "session.json"), v)
}
func (s *Store) marker(v Object, label string, b Object) error {
	return s.Write(Object{"schema_version": 1, "event_id": fmt.Sprintf("%s:capture:%s:%s", v["vm_id"], v["session_id"], label), "timestamp": b["timestamp"], "vm_id": v["vm_id"], "source": "control", "kind": "marker", "origin": "control", "capture_session_id": v["session_id"], "label": label, "audit_serial": b["serial"]}, filepath.Join(s.directory(str(v["session_id"])), "events.jsonl"))
}
func InWindow(e, w Object) bool {
	if e["vm_id"] != w["vm_id"] {
		return false
	}
	if e["source"] != "auditd" {
		return e["capture_session_id"] == w["session_id"]
	}
	start := obj(w["start_boundary"])
	if len(start) == 0 {
		return false
	}
	serial := e["audit_serial"]
	if serial == nil {
		parts := strings.Split(str(e["event_id"]), ":")
		n, _ := strconv.Atoi(parts[len(parts)-1])
		serial = n
	}
	if num(serial) <= num(start["serial"]) || moment(e["timestamp"]) < moment(start["timestamp"]) {
		return false
	}
	end := obj(w["stop_boundary"])
	return len(end) == 0 || (num(serial) < num(end["serial"]) && moment(e["timestamp"]) <= moment(end["timestamp"]))
}
func (s *Store) captureLock() (func(), error) {
	if e := os.MkdirAll(s.Root, 0700); e != nil {
		return nil, e
	}
	return lock(filepath.Join(s.Root, ".capture.lock"))
}
func (s *Store) Start(id, vm string, boundary func() (Object, error)) (Object, error) {
	if e := ValidSession(id); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(s.Root, 0700); e != nil {
		return nil, e
	}
	unlock, e := lock(filepath.Join(s.Root, ".lifecycle.lock"))
	if e != nil {
		return nil, e
	}
	defer unlock()
	release, e := s.captureLock()
	if e != nil {
		return nil, e
	}
	state, e := s.Current()
	if e != nil {
		release()
		return nil, e
	}
	if state != nil && state["phase"] != "stopped" {
		if state["session_id"] != id {
			release()
			return nil, errors.New("another recording session is already active")
		}
		if state["boot_id"] != s.Boot {
			release()
			return nil, errors.New("machine rebooted during recording; manual recovery is required")
		}
		if state["phase"] == "recording" {
			release()
			return state, nil
		}
		if state["phase"] != "starting" {
			release()
			return nil, errors.New("session is stopping; retry stop before starting another")
		}
	} else {
		entries, err := os.ReadDir(s.directory(id))
		if err != nil && !os.IsNotExist(err) {
			release()
			return nil, err
		}
		if len(entries) > 0 {
			release()
			return nil, errors.New("session ID has already been used; choose a new ID")
		}
		if e = os.MkdirAll(s.directory(id), 0700); e != nil {
			release()
			return nil, e
		}
		state = Object{"schema_version": 1, "session_id": id, "vm_id": vm, "boot_id": s.Boot, "phase": "starting", "requested_at": now()}
		if e = s.save(state); e != nil {
			release()
			return nil, e
		}
	}
	release()
	b, e := boundary()
	if e != nil {
		return nil, e
	}
	release, e = s.captureLock()
	if e != nil {
		return nil, e
	}
	defer release()
	state["phase"] = "recording"
	state["started_at"] = b["timestamp"]
	state["start_boundary"] = b
	if e = s.save(state); e != nil {
		return nil, e
	}
	if e = s.marker(state, "recording_started", b); e != nil {
		return nil, e
	}
	return state, nil
}
func (s *Store) Record(event Object) (bool, error) {
	release, e := s.captureLock()
	if e != nil {
		return false, e
	}
	defer release()
	state, e := s.Current()
	if e != nil {
		return false, e
	}
	if state == nil || (state["phase"] != "recording" && state["phase"] != "stopping") || state["boot_id"] != s.Boot {
		return false, nil
	}
	if event["source"] != "auditd" && state["phase"] != "recording" {
		return false, nil
	}
	tagged := clone(event)
	tagged["capture_session_id"] = state["session_id"]
	if !InWindow(tagged, state) {
		return false, nil
	}
	e = s.Write(tagged, filepath.Join(s.directory(str(state["session_id"])), "events.jsonl"))
	return e == nil, e
}
func (s *Store) Stop(id string, boundary func() (Object, error), finalize func(Object) (Object, error)) (Object, error) {
	if e := ValidSession(id); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(s.Root, 0700); e != nil {
		return nil, e
	}
	unlock, e := lock(filepath.Join(s.Root, ".lifecycle.lock"))
	if e != nil {
		return nil, e
	}
	defer unlock()
	release, e := s.captureLock()
	if e != nil {
		return nil, e
	}
	state, e := s.Get(id)
	if e != nil {
		release()
		return nil, e
	}
	current, e := s.Current()
	if e != nil {
		release()
		return nil, e
	}
	if state["phase"] == "stopped" {
		release()
		if current != nil && current["session_id"] != id && current["phase"] != "stopped" {
			return nil, errors.New("another session is active; validation of the old attempt is blocked")
		}
		return state, nil
	}
	if current == nil || current["session_id"] != id {
		release()
		return nil, errors.New("requested session is not the active session")
	}
	if state["phase"] != "recording" && state["phase"] != "stopping" {
		release()
		return nil, errors.New("recording has not started successfully")
	}
	if state["boot_id"] != s.Boot {
		release()
		return nil, errors.New("machine rebooted during recording; manual recovery is required")
	}
	if state["phase"] == "recording" {
		state["phase"] = "stopping"
		state["stop_requested_at"] = now()
		e = s.save(state)
	}
	release()
	if e != nil {
		return nil, e
	}
	if state["stop_boundary"] == nil {
		b, err := boundary()
		if err != nil {
			return nil, err
		}
		release, e = s.captureLock()
		if e != nil {
			return nil, e
		}
		state["stopped_at"] = b["timestamp"]
		state["stop_boundary"] = b
		e = s.save(state)
		if e == nil {
			e = s.marker(state, "recording_stopped", b)
		}
		release()
		if e != nil {
			return nil, e
		}
	}
	sealed := clone(state)
	sealed["phase"] = "stopped"
	sealed["sealed_at"] = now()
	artifacts, e := finalize(sealed)
	if e != nil {
		return nil, e
	}
	release, e = s.captureLock()
	if e != nil {
		return nil, e
	}
	defer release()
	sealed["artifacts"] = artifacts
	if e = s.save(sealed); e != nil {
		return nil, e
	}
	return sealed, nil
}

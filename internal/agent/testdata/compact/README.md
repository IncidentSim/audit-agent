These 25 fixtures were generated from the original Python compact exporter before
the Go migration. They contain synthetic events, the original manifest/options,
the expected complete packet and the expected provenance references.

The Go suite compares decoded JSON objects, so differences in key order and JSON
whitespace do not affect the result. Cases cover Bash start/finish and unknown
statuses, PID reuse, parallel sessions, background effects, Unicode, secrets,
repeated commands/effects, detail budgets, SSH/control noise and security notes.

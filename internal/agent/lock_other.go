//go:build !linux

package agent

import (
	"os"
	"sync"
)

var localLocks sync.Map

func lock(path string) (func(), error) {
	v, _ := localLocks.LoadOrStore(path, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		m.Unlock()
		return nil, e
	}
	return func() { f.Close(); m.Unlock() }, nil
}
func syncDirectory(string) error { return nil }

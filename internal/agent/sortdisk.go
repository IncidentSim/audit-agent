package agent

import (
	"bufio"
	"container/heap"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sort"
)

// Each sort pass uses bounded chunks and a bounded merge fan-in. Audit history
// can be much larger than the guest's available heap.
const sortChunkBytes = 2 << 20
const sortMergeFiles = 16

type sortRecord struct {
	key  string
	data []byte
}

type diskSort struct {
	dir   string
	rows  []sortRecord
	bytes int
	runs  []string
}

func (s *diskSort) Add(key string, data []byte) error {
	s.rows = append(s.rows, sortRecord{key: key, data: append([]byte(nil), data...)})
	s.bytes += len(key) + len(data) + 48
	if s.bytes >= sortChunkBytes {
		return s.flush()
	}
	return nil
}

func writeSortRecord(w io.Writer, row sortRecord) error {
	var sizes [8]byte
	binary.LittleEndian.PutUint32(sizes[:4], uint32(len(row.key)))
	binary.LittleEndian.PutUint32(sizes[4:], uint32(len(row.data)))
	for _, b := range [][]byte{sizes[:], []byte(row.key), row.data} {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

func readSortRecord(r io.Reader) (sortRecord, error) {
	var sizes [8]byte
	if _, err := io.ReadFull(r, sizes[:]); err != nil {
		return sortRecord{}, err
	}
	keySize, dataSize := binary.LittleEndian.Uint32(sizes[:4]), binary.LittleEndian.Uint32(sizes[4:])
	if keySize > 32<<20 || dataSize > 64<<20 {
		return sortRecord{}, errors.New("invalid temporary sort record")
	}
	key, data := make([]byte, keySize), make([]byte, dataSize)
	if _, err := io.ReadFull(r, key); err != nil {
		return sortRecord{}, err
	}
	if _, err := io.ReadFull(r, data); err != nil {
		return sortRecord{}, err
	}
	return sortRecord{string(key), data}, nil
}

func (s *diskSort) flush() error {
	if len(s.rows) == 0 {
		return nil
	}
	sort.SliceStable(s.rows, func(i, j int) bool { return s.rows[i].key < s.rows[j].key })
	file, err := os.CreateTemp(s.dir, "sort-*")
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	for _, row := range s.rows {
		if err = writeSortRecord(writer, row); err != nil {
			break
		}
	}
	if err == nil {
		err = writer.Flush()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(file.Name())
		return err
	}
	s.runs = append(s.runs, file.Name())
	s.rows, s.bytes = nil, 0
	return nil
}

type mergeHead struct {
	row   sortRecord
	index int
}

type mergeHeap []mergeHead

func (h mergeHeap) Len() int { return len(h) }
func (h mergeHeap) Less(i, j int) bool {
	if h[i].row.key == h[j].row.key {
		return h[i].index < h[j].index
	}
	return h[i].row.key < h[j].row.key
}
func (h mergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(v any)   { *h = append(*h, v.(mergeHead)) }
func (h *mergeHeap) Pop() any {
	v := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return v
}

func mergeSortRuns(files []string, emit func(sortRecord) error) error {
	opened := []*os.File{}
	defer func() {
		for _, file := range opened {
			file.Close()
		}
	}()
	readers := []*bufio.Reader{}
	queue := &mergeHeap{}
	for i, name := range files {
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		opened = append(opened, file)
		reader := bufio.NewReader(file)
		readers = append(readers, reader)
		row, err := readSortRecord(reader)
		if err == nil {
			heap.Push(queue, mergeHead{row, i})
		} else if err != io.EOF {
			return err
		}
	}
	for queue.Len() > 0 {
		head := heap.Pop(queue).(mergeHead)
		if err := emit(head.row); err != nil {
			return err
		}
		row, err := readSortRecord(readers[head.index])
		if err == nil {
			heap.Push(queue, mergeHead{row, head.index})
		} else if err != io.EOF {
			return err
		}
	}
	return nil
}

func (s *diskSort) Finish(emit func(sortRecord) error) error {
	if err := s.flush(); err != nil {
		return err
	}
	for len(s.runs) > sortMergeFiles {
		next := []string{}
		for start := 0; start < len(s.runs); start += sortMergeFiles {
			end := start + sortMergeFiles
			if end > len(s.runs) {
				end = len(s.runs)
			}
			file, err := os.CreateTemp(s.dir, "merge-*")
			if err != nil {
				return err
			}
			writer := bufio.NewWriter(file)
			err = mergeSortRuns(s.runs[start:end], func(row sortRecord) error { return writeSortRecord(writer, row) })
			if err == nil {
				err = writer.Flush()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			next = append(next, file.Name())
			for _, name := range s.runs[start:end] {
				if err := os.Remove(name); err != nil {
					return err
				}
			}
		}
		s.runs = next
	}
	return mergeSortRuns(s.runs, emit)
}

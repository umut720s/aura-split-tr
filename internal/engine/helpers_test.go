package engine

import (
	"bytes"
	"sync"
	"time"

	"github.com/sagernet/sing/service/filemanager"
)

type fileManager = filemanager.Manager

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func sleepShort() { time.Sleep(10 * time.Millisecond) }

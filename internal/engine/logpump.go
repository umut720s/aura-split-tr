package engine

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// logQueueSize bounds the number of log lines waiting for the sink.
	logQueueSize = 1024
	// maxLogLine is the longest line kept in one piece; longer lines are
	// split.
	maxLogLine = 8 << 10
	// logDrainTimeout bounds how long shutdown waits for queued lines.
	logDrainTimeout = 2 * time.Second
)

// logPump decouples sing-box from the log sink so that sing-box writes
// never block for long, even when the sink stalls (slow disk, full disk):
//
//   - sing-box writes to the write end of an os.Pipe (it needs an *os.File);
//   - a reader goroutine per pipe reads continuously, splits lines and
//     offers them to a bounded queue without blocking; when the queue is
//     full the line is dropped and counted;
//   - one writer goroutine drains the queue into the sink. Sink errors are
//     counted and never stop the draining. Dropped lines and failed writes
//     are reported in the log as soon as the sink accepts a line again.
//
// Engine messages go through the same queue (Log never blocks).
type logPump struct {
	sink io.Writer
	// redact, if set before the first line, rewrites each line on the
	// writer goroutine (secret removal); producers never wait for it.
	redact func([]byte) []byte
	queue  chan []byte
	stop   chan struct{}
	done   chan struct{} // closed when the writer goroutine exits

	dropped atomic.Uint64

	mu      sync.Mutex
	closed  bool
	pipes   map[*os.File]struct{} // write ends currently handed out
	readers sync.WaitGroup
}

func newLogPump(sink io.Writer, size int) *logPump {
	if size < 1 {
		size = logQueueSize
	}
	p := &logPump{
		sink:  sink,
		queue: make(chan []byte, size),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		pipes: make(map[*os.File]struct{}),
	}
	go p.writeLoop()
	return p
}

// offer queues line without blocking; it is dropped if the queue is full.
// The queue channel is never closed, so offering after Close is safe.
func (p *logPump) offer(line []byte) {
	select {
	case p.queue <- line:
	default:
		p.dropped.Add(1)
	}
}

// Log queues one engine message in the sing-box log format.
func (p *logPump) Log(level, msg string) { p.offer(formatLine(level, msg)) }

// Pipe returns a new write end for sing-box. A reader goroutine forwards
// everything written to it until every copy of the write end is closed.
func (p *logPump) Pipe() (*os.File, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, os.ErrClosed
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	p.pipes[w] = struct{}{}
	p.readers.Add(1)
	go p.readLoop(r, w)
	return w, nil
}

func (p *logPump) readLoop(r, w *os.File) {
	defer p.readers.Done()
	defer r.Close()
	br := bufio.NewReaderSize(r, maxLogLine)
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			buf := append(make([]byte, 0, len(line)+1), line...)
			if buf[len(buf)-1] != '\n' {
				buf = append(buf, '\n')
			}
			p.offer(buf)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			break // EOF: sing-box closed its log file; or a broken pipe
		}
	}
	p.mu.Lock()
	delete(p.pipes, w)
	p.mu.Unlock()
}

func (p *logPump) writeLoop() {
	defer close(p.done)
	var failed uint64
	write := func(line []byte) {
		if p.redact != nil {
			line = p.redact(line)
		}
		if _, err := p.sink.Write(line); err != nil {
			failed++
			return
		}
		if failed > 0 {
			n := failed
			failed = 0
			if _, err := p.sink.Write(formatLine("WARN", fmt.Sprintf("%d log writes failed before this line", n))); err != nil {
				failed++
			}
		}
	}
	flushDropped := func() {
		if n := p.dropped.Swap(0); n > 0 {
			write(formatLine("WARN", fmt.Sprintf("%d log lines dropped (log queue full)", n)))
		}
	}
	for {
		select {
		case line := <-p.queue:
			flushDropped()
			write(line)
		case <-p.stop:
			for {
				select {
				case line := <-p.queue:
					write(line)
				default:
					flushDropped()
					return
				}
			}
		}
	}
}

// Close closes every write end still handed out (sing-box normally closed
// them already when its box was closed), waits for the readers to reach
// EOF and for the writer to drain the queue, in total at most timeout.
// The caller closes the sink afterwards; a writer still blocked in the
// sink after the timeout only finds a closed sink.
func (p *logPump) Close(timeout time.Duration) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	pipes := make([]*os.File, 0, len(p.pipes))
	for w := range p.pipes {
		pipes = append(pipes, w)
	}
	p.mu.Unlock()
	for _, w := range pipes {
		_ = w.Close() // already closed by sing-box is fine
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	readersDone := make(chan struct{})
	go func() {
		p.readers.Wait()
		close(readersDone)
	}()
	select {
	case <-readersDone:
	case <-deadline.C:
		close(p.stop)
		return
	}
	close(p.stop)
	select {
	case <-p.done:
	case <-deadline.C:
	}
}

// formatLine renders one engine message in the sing-box log format.
func formatLine(level, msg string) []byte {
	msg = strings.NewReplacer("\r", " ", "\n", " ").Replace(msg)
	return []byte(fmt.Sprintf("%s %s [aurasplit] %s\n", time.Now().Format("-0700 2006-01-02 15:04:05"), level, msg))
}

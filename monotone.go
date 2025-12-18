package monotone

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"runtime"
	"sync"
	"unsafe"

	_ "embed"

	"github.com/ebitengine/purego"
)

// monotone 1.2.0
//
//go:embed libs/libmonotone.so
var libmonotoneBytes []byte

var (
	free func(uintptr)

	monotone_init    func() uintptr
	monotone_free    func(uintptr)
	monotone_error   func(uintptr) string
	monotone_open    func(uintptr, string) int
	monotone_execute func(uintptr, string, *uintptr) int32
	monotone_write   func(uintptr, *monotoneEvent, int) int
	monotone_cursor  func(uintptr, uintptr, *monotoneEvent) uintptr
	monotone_read    func(uintptr, *monotoneEvent) int
	monotone_next    func(uintptr) int
)

var registerLib = sync.OnceFunc(func() {
	libmonotonePath := os.Getenv("LIBMONOTONE_PATH")
	if len(libmonotonePath) == 0 {
		path, closer, err := dumpEmbeddedLib()
		if err != nil {
			panic(fmt.Sprintf("dump libmonotone: %s", err))
		}
		defer func() {
			if err := closer(); err != nil {
				panic(fmt.Sprintf("error removing %s: %s", path, err))
			}
		}()

		libmonotonePath = path
	}

	libc, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		panic(fmt.Sprintf("open libc.so.6: %s", err))
	}

	libmonotone, err := purego.Dlopen(libmonotonePath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		panic(fmt.Sprintf("open libmonotone.so: %s", err))
	}

	purego.RegisterLibFunc(&free, libc, "free")
	purego.RegisterLibFunc(&monotone_init, libmonotone, "monotone_init")
	purego.RegisterLibFunc(&monotone_free, libmonotone, "monotone_free")
	purego.RegisterLibFunc(&monotone_open, libmonotone, "monotone_open")
	purego.RegisterLibFunc(&monotone_error, libmonotone, "monotone_error")
	purego.RegisterLibFunc(&monotone_write, libmonotone, "monotone_write")
	purego.RegisterLibFunc(&monotone_cursor, libmonotone, "monotone_cursor")
	purego.RegisterLibFunc(&monotone_read, libmonotone, "monotone_read")
	purego.RegisterLibFunc(&monotone_next, libmonotone, "monotone_next")
	purego.RegisterLibFunc(&monotone_execute, libmonotone, "monotone_execute")
})

const (
	flagsWrite  = 0
	flagsDelete = 1
)

var ErrClosed = errors.New("closed")

type monotoneEvent struct {
	Flags     int
	Id        uint64
	Key       *byte
	KeySize   uint
	Value     *byte
	ValueSize uint
}

func (e *monotoneEvent) Event() *Event {
	return &Event{
		Id:    e.Id,
		Key:   unsafe.Slice(e.Key, e.KeySize),
		Value: unsafe.Slice(e.Value, e.ValueSize),
	}
}

type Event struct {
	Id    uint64 `json:"id,omitempty"`
	Key   []byte `json:"key,omitempty"`
	Value []byte `json:"value,omitempty"`
}

func (a *Event) Equal(b *Event) bool {
	return a.Id == b.Id && bytes.Equal(a.Key, b.Key) && bytes.Equal(a.Value, b.Value)
}

func (e *Event) String() string {
	bs, _ := json.Marshal(e)
	return string(bs)
}

func New() *Monotone {
	registerLib()

	return &Monotone{
		env: monotone_init(),
	}
}

type Monotone struct {
	env    uintptr
	closed bool

	mu sync.RWMutex
}

func (m *Monotone) Open(s string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	rc := monotone_open(m.env, s)
	if rc == -1 {
		return m.Error()
	}
	return nil
}

func (m *Monotone) Read(key *Event, n int) ([]*Event, error) {
	cur, err := m.Cursor(key, false)
	if err != nil {
		return nil, fmt.Errorf("cursor: %w", err)
	}
	return cur.Read(n)
}

func (m *Monotone) Write(batch []*Event) error {
	return m.write(flagsWrite, batch)
}

func (m *Monotone) Delete(batch []*Event) error {
	return m.write(flagsDelete, batch)
}

func (m *Monotone) write(flags int, batch []*Event) error {
	if len(batch) == 0 {
		return nil
	}

	mbatch := make([]monotoneEvent, len(batch))
	for i, event := range batch {
		mbatch[i] = monotoneEvent{
			Flags:     flags,
			Id:        event.Id,
			Key:       unsafe.SliceData(event.Key),
			KeySize:   uint(len(event.Key)),
			Value:     unsafe.SliceData(event.Value),
			ValueSize: uint(len(event.Value)),
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrClosed
	}

	rc := monotone_write(m.env, unsafe.SliceData(mbatch), len(mbatch))
	if rc == -1 {
		return m.Error()
	}

	for i := range batch {
		runtime.KeepAlive(batch[i])
	}

	return nil
}

func (m *Monotone) Cursor(key *Event, exclusive bool) (*Cursor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrClosed
	}

	return &Cursor{
		db:        m,
		key:       key,
		exclusive: exclusive,
	}, nil
}

func (m *Monotone) Execute(command string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrClosed
	}

	var output uintptr
	rc := monotone_execute(m.env, command, &output)
	if rc == -1 {
		return nil, m.Error()
	}

	data := goStringBytes(output)
	free(output)

	return data, nil
}

func (m *Monotone) Error() error {
	return errors.New(monotone_error(m.env))
}

func (m *Monotone) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}
	m.closed = true

	monotone_free(m.env)
}

type Cursor struct {
	db        *Monotone
	key       *Event
	cur       uintptr
	exclusive bool
}

func (c *Cursor) open() error {
	c.db.mu.RLock()
	if c.db.closed {
		c.db.mu.RUnlock()
		return ErrClosed
	}

	var cur uintptr
	if c.key == nil {
		cur = monotone_cursor(c.db.env, 0, nil)
	} else {
		cur = monotone_cursor(c.db.env, 0, &monotoneEvent{
			Id:        c.key.Id,
			Key:       unsafe.SliceData(c.key.Key),
			KeySize:   uint(len(c.key.Key)),
			Value:     unsafe.SliceData(c.key.Value),
			ValueSize: uint(len(c.key.Value)),
		})
	}

	if cur == 0 {
		c.db.mu.RUnlock()
		return c.db.Error()
	}
	c.cur = cur

	return nil
}

func (c *Cursor) close() {
	monotone_free(c.cur)
	c.cur = 0
	c.db.mu.RUnlock()
}

func (c *Cursor) read() (*Event, error) {
	mevent := new(monotoneEvent)
	rc := monotone_read(c.cur, mevent)
	if rc == -1 {
		return nil, c.db.Error()
	}
	if rc == 0 {
		return nil, io.EOF
	}
	return mevent.Event(), nil
}

func (c *Cursor) next() error {
	rc := monotone_next(c.cur)
	if rc == -1 {
		return c.db.Error()
	}
	return nil
}

func (c *Cursor) Read(n int) (events []*Event, err error) {
	if err = c.open(); err != nil {
		return
	}
	defer c.close()

	defer func() {
		if ln := len(events); ln > 0 {
			c.exclusive = true
			c.key = events[ln-1]
		}
	}()

	if c.exclusive {
		if _, err = c.read(); err != nil {
			return
		}
		if err = c.next(); err != nil {
			return
		}
	}

	events = make([]*Event, 0, n)
	var event *Event
	for {
		if event, err = c.read(); err != nil {
			return
		}

		events = append(events, event)
		if len(events) >= n {
			return
		}

		if err = c.next(); err != nil {
			return
		}
	}
}

func (c *Cursor) Stream() (iter.Seq[*Event], func() error) {
	var err error
	return func(yield func(*Event) bool) {
		if err = c.open(); err != nil {
			return
		}
		defer c.close()

		var advanceEvent *Event
		defer func() {
			if advanceEvent != nil {
				c.exclusive = true
				c.key = advanceEvent
			}
		}()

		if c.exclusive {
			if _, err = c.read(); err != nil {
				return
			}
			if err = c.next(); err != nil {
				return
			}
		}

		var event *Event
		for {
			if event, err = c.read(); err != nil {
				return
			}

			advanceEvent = event
			if !yield(event) {
				return
			}

			if err = c.next(); err != nil {
				return
			}
		}
	}, func() error { return err }
}

func (c *Cursor) Key() *Event {
	return c.key
}

func goStringBytes(c uintptr) []byte {
	ptr := *(*unsafe.Pointer)(unsafe.Pointer(&c))
	if ptr == nil {
		return nil
	}
	var length int
	for {
		if *(*byte)(unsafe.Add(ptr, uintptr(length))) == '\x00' {
			break
		}
		length++
	}
	bs := make([]byte, length)
	copy(bs, unsafe.Slice((*byte)(ptr), length))
	return bs
}

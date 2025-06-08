package monotone

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unsafe"

	_ "embed"

	"github.com/ebitengine/purego"
)

// https://github.com/pmwkaa/monotone/commit/5a77290e72d8b1a2b0ca22f24acd014c9940677d
//
//go:embed libs/libmonotone.so
var libmonotoneBytes []byte

var (
	libc        uintptr
	libmonotone uintptr
)

var (
	free func(uintptr)

	monotone_init    func() uintptr
	monotone_free    func(uintptr) int32
	monotone_open    func(uintptr, string) int32
	monotone_error   func(uintptr) string
	monotone_write   func(uintptr, unsafe.Pointer, int32) int32
	monotone_cursor  func(uintptr, uintptr, unsafe.Pointer) uintptr
	monotone_read    func(uintptr, unsafe.Pointer) int32
	monotone_next    func(uintptr) int32
	monotone_execute func(uintptr, string, *uintptr) int32
)

func init() {
	path, closer, err := dumpEmbed()
	if err != nil {
		panic(fmt.Sprintf("dump libmonotone: %s", err))
	}
	defer func() {
		if err := closer(); err != nil {
			panic(fmt.Sprintf("error removing %s: %s", path, err))
		}
	}()

	libc, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		panic(fmt.Sprintf("open libc.so.6: %s", err))
	}

	libmonotone, err := purego.Dlopen(path, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
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
}

const (
	flagsWrite  = 0
	flagsDelete = 1
)

var ErrClosed = errors.New("closed")

func newMonotoneEvent(flags int32, event *Event) monotoneEvent {
	keyPtr, keySize := sliceBytesPtr(event.Key)
	valuePtr, valueSize := sliceBytesPtr(event.Value)

	return monotoneEvent{
		Flags:     flags,
		Id:        event.Id,
		Key:       keyPtr,
		KeySize:   keySize,
		Value:     valuePtr,
		ValueSize: valueSize,
	}
}

type monotoneEvent struct {
	Flags     int32
	Id        uint64
	Key       unsafe.Pointer
	KeySize   uint64
	Value     unsafe.Pointer
	ValueSize uint64
}

func (e *monotoneEvent) Event() *Event {
	return &Event{
		Id:    e.Id,
		Key:   sliceBytes(e.Key, e.KeySize),
		Value: sliceBytes(e.Value, e.ValueSize),
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
	env := monotone_init()
	return &Monotone{
		env: env,
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
	cur, err := m.Cursor(key)
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

func (m *Monotone) write(flags int32, batch []*Event) error {
	if len(batch) == 0 {
		return nil
	}

	mbatch := make([]monotoneEvent, len(batch))
	for i, event := range batch {
		mbatch[i] = newMonotoneEvent(flags, event)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrClosed
	}

	rc := monotone_write(m.env, unsafe.Pointer(unsafe.SliceData(mbatch)), int32(len(mbatch)))
	if rc == -1 {
		return m.Error()
	}
	return nil
}

func (m *Monotone) Cursor(key *Event) (*Cursor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrClosed
	}

	var mkey monotoneEvent
	if key != nil {
		mkey = newMonotoneEvent(0, key)
	}

	return &Cursor{
		db:  m,
		key: &mkey,
	}, nil
}

func (m *Monotone) Execute(command string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrClosed
	}

	var result uintptr
	rc := monotone_execute(m.env, command, &result)
	if rc == -1 {
		return nil, m.Error()
	}
	return goStringBytes(result), nil
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
	db     *Monotone
	key    *monotoneEvent
	cur    uintptr
	active bool
}

func (c *Cursor) open() error {
	c.db.mu.RLock()
	if c.db.closed {
		c.db.mu.RUnlock()
		return ErrClosed
	}
	cur := monotone_cursor(c.db.env, 0, unsafe.Pointer(c.key))
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

func (c *Cursor) advance(event *Event) {
	c.key.Id = event.Id
	c.key.Key, c.key.KeySize = sliceBytesPtr(event.Key)
}

func (c *Cursor) read() (*Event, error) {
	mevent := new(monotoneEvent)
	rc := monotone_read(c.cur, unsafe.Pointer(mevent))
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
			c.active = true
			c.advance(events[ln-1])
		}
	}()

	if c.active { // skip already read event
		if _, err = c.read(); err != nil {
			return
		}
		if err = c.next(); err != nil {
			return
		}
	}

	var event *Event
	events = make([]*Event, 0, n)
	for {
		event, err = c.read()
		if err != nil {
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

func (c *Cursor) Key() *Event {
	return c.key.Event()
}

func (c *Cursor) Active() bool {
	return c.active
}

func sliceBytesPtr(bs []byte) (unsafe.Pointer, uint64) {
	if len(bs) == 0 {
		return nil, 0
	}
	return unsafe.Pointer(unsafe.SliceData(bs)), uint64(len(bs))
}

func sliceBytes(ptr unsafe.Pointer, size uint64) []byte {
	if size == 0 {
		return nil
	}
	bs := make([]byte, size)
	copy(bs, unsafe.Slice((*byte)(ptr), size))
	return bs
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
	free(c)
	return bs
}

package monotone

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"unsafe"

	"os"

	"github.com/ebitengine/purego"
)

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
	libc, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		panic(fmt.Sprintf("open libc.so.6: %s", err))
	}

	libmonotonePath := os.Getenv("LIBMONOTONE_PATH")
	if len(libmonotonePath) == 0 {
		panic("env LIBMONOTONE_PATH not found")
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
}

const (
	flagsWrite  = 0
	flagsDelete = 1
)

var ErrClosed = errors.New("closed")

func newMonotoneEvent(flags int32, id uint64, key []byte, value []byte) monotoneEvent {
	keyPtr, keySize := sliceBytesPtr(key)
	valuePtr, valueSize := sliceBytesPtr(value)

	return monotoneEvent{
		Flags:     flags,
		Id:        id,
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
	Id    uint64
	Key   []byte
	Value []byte
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
	for i, v := range batch {
		mbatch[i] = newMonotoneEvent(flags, v.Id, v.Key, v.Value)
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

func (m *Monotone) Cursor(key Event) (*Cursor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, ErrClosed
	}

	mkey := newMonotoneEvent(0, key.Id, key.Key, nil)

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
	db  *Monotone
	key *monotoneEvent
	cur uintptr
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

func (c *Cursor) advance(id uint64, key []byte) {
	c.key.Id = id
	c.key.Key, c.key.KeySize = sliceBytesPtr(key)
}

func (c *Cursor) close() {
	monotone_free(c.cur)
	c.cur = 0
	c.db.mu.RUnlock()
}

func (c *Cursor) Read(n int) ([]*Event, error) {
	if err := c.open(); err != nil {
		return nil, err
	}
	defer c.close()

	var event *Event
	defer func() {
		if event == nil {
			return
		}
		c.advance(event.Id, event.Key)
	}()

	events := make([]*Event, 0, n)
	for {
		var mevent monotoneEvent
		rc := monotone_read(c.cur, unsafe.Pointer(&mevent))
		if rc == -1 {
			return nil, c.db.Error()
		}
		if rc == 0 {
			return events, io.EOF
		}

		event = mevent.Event()
		if len(events) >= n {
			return events, nil
		}
		events = append(events, event)

		rc = monotone_next(c.cur)
		if rc == -1 {
			return nil, c.db.Error()
		}
	}
}

func (c *Cursor) Key() *Event {
	return c.key.Event()
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

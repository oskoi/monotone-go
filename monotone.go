package monotone

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/ebitengine/purego"
)

var (
	libc        uintptr
	libmonotone uintptr
)

var (
	free func(unsafe.Pointer)

	monotone_init    func() unsafe.Pointer
	monotone_free    func(unsafe.Pointer) int
	monotone_open    func(unsafe.Pointer, string) int
	monotone_error   func(unsafe.Pointer) string
	monotone_write   func(unsafe.Pointer, []monotoneEvent, int) int
	monotone_cursor  func(unsafe.Pointer, unsafe.Pointer, *monotoneEvent) unsafe.Pointer
	monotone_read    func(unsafe.Pointer, *monotoneEvent) int
	monotone_next    func(unsafe.Pointer) int
	monotone_execute func(unsafe.Pointer, string, *unsafe.Pointer) int
)

func init() {
	libc, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		panic(fmt.Sprintf("open libc.so.6: %s", err))
	}

	libmonotone, err := purego.Dlopen("./libmonotone.so", purego.RTLD_LAZY)
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

func newMonotoneEvent(flags int, id uint64, key string, value string) monotoneEvent {
	var keyPtr, valuePtr unsafe.Pointer
	var keySize, valueSize uint64
	if len(key) > 0 {
		keyPtr = unsafe.Pointer(unsafe.StringData(key))
		keySize = uint64(len(key))
	}
	if len(value) > 0 {
		valuePtr = unsafe.Pointer(unsafe.StringData(value))
		valueSize = uint64(len(value))
	}
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
	Flags     int
	Id        uint64
	Key       unsafe.Pointer
	KeySize   uint64
	Value     unsafe.Pointer
	ValueSize uint64
}

type Event struct {
	Id    uint64
	Key   string
	Value string
}

func New() *Monotone {
	env := monotone_init()
	return &Monotone{
		env: env,
	}
}

type Monotone struct {
	env unsafe.Pointer
}

func (m *Monotone) Open(s string) error {
	rc := monotone_open(m.env, s)
	if rc == -1 {
		return m.Error()
	}
	return nil
}

func (m *Monotone) Write(batch []Event) error {
	return m.write(flagsWrite, batch)
}

func (m *Monotone) Delete(batch []Event) error {
	return m.write(flagsDelete, batch)
}

func (m *Monotone) write(flags int, batch []Event) error {
	monotoneBatch := make([]monotoneEvent, len(batch))
	for i, v := range batch {
		monotoneBatch[i] = newMonotoneEvent(flags, v.Id, v.Key, v.Value)
	}
	rc := monotone_write(m.env, monotoneBatch, len(monotoneBatch))
	if rc == -1 {
		return m.Error()
	}
	return nil
}

func (m *Monotone) Cursor(key Event) (*Cursor, error) {
	monotoneKey := newMonotoneEvent(0, key.Id, key.Key, key.Value)
	cur := monotone_cursor(m.env, nil, &monotoneKey)
	if cur == nil {
		return nil, m.Error()
	}
	return &Cursor{
		env: m,
		cur: cur,
	}, nil
}

func (m *Monotone) Execute(command string) (string, error) {
	var result unsafe.Pointer
	rc := monotone_execute(m.env, command, &result)
	if rc == -1 {
		return "", m.Error()
	}
	return goString(result), nil
}

func (m *Monotone) Error() error {
	return errors.New(monotone_error(m.env))
}

func (m *Monotone) Close() {
	monotone_free(unsafe.Pointer(m.env))
}

type Cursor struct {
	env   *Monotone
	cur   unsafe.Pointer
	total int
}

func (c *Cursor) Read() (*Event, error) {
	if c.total > 0 {
		rc := monotone_next(c.cur)
		if rc == -1 {
			return nil, c.env.Error()
		}
	}

	var monotoneEvent monotoneEvent
	rc := monotone_read(c.cur, &monotoneEvent)
	if rc == -1 {
		return nil, c.env.Error()
	}
	if rc == 0 {
		return nil, io.EOF
	}

	c.total++

	var key, value string
	if monotoneEvent.KeySize > 0 {
		key = strings.Clone(unsafe.String((*byte)(monotoneEvent.Key), monotoneEvent.KeySize))
		free(monotoneEvent.Key)
	}
	if monotoneEvent.ValueSize > 0 {
		value = strings.Clone(unsafe.String((*byte)(monotoneEvent.Value), monotoneEvent.ValueSize))
		free(monotoneEvent.Value)
	}

	return &Event{
		Id:    monotoneEvent.Id,
		Key:   key,
		Value: value,
	}, nil
}

func (c *Cursor) Total() int {
	return c.total
}

func (c *Cursor) Close() {
	monotone_free(unsafe.Pointer(c.cur))
}

func goString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	var length int
	for {
		if *(*byte)(unsafe.Add(ptr, uintptr(length))) == '\x00' {
			break
		}
		length++
	}
	str := strings.Clone(string(unsafe.Slice((*byte)(ptr), length)))
	free(ptr)
	return str
}

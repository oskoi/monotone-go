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
	monotone_write   func(unsafe.Pointer, []Event, int) int
	monotone_cursor  func(unsafe.Pointer, unsafe.Pointer, *Event) unsafe.Pointer
	monotone_read    func(unsafe.Pointer, *Event) int
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
	FlagWrite  = 0
	FlagDelete = 1
)

func NewWriteEvent(id uint64, key string, value string) Event {
	return newEvent(FlagWrite, id, key, value)
}

func NewDeleteEvent(id uint64, key string, value string) Event {
	return newEvent(FlagDelete, id, key, value)
}

func newEvent(flags int, id uint64, key string, value string) Event {
	keyPtr := unsafe.Pointer(unsafe.StringData(key))
	valuePtr := unsafe.Pointer(unsafe.StringData(value))
	return Event{
		Flags:     flags,
		Id:        id,
		Key:       keyPtr,
		KeySize:   uint64(len(key)),
		Value:     valuePtr,
		ValueSize: uint64(len(value)),
	}
}

type Event struct {
	Flags     int
	Id        uint64
	Key       unsafe.Pointer
	KeySize   uint64
	Value     unsafe.Pointer
	ValueSize uint64
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
	rc := monotone_write(m.env, batch, len(batch))
	if rc == -1 {
		return m.Error()
	}
	return nil
}

func (m *Monotone) Cursor(key Event) (*Cursor, error) {
	cur := monotone_cursor(m.env, nil, &key)
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

	var event Event
	rc := monotone_read(c.cur, &event)
	if rc == -1 {
		return nil, c.env.Error()
	}
	if rc == 0 {
		return nil, io.EOF
	}

	c.total++

	return &event, nil
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

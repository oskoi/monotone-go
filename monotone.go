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
	monotone_write   func(unsafe.Pointer, []MonotoneEvent, int) int
	monotone_cursor  func(unsafe.Pointer, unsafe.Pointer, *MonotoneEvent) unsafe.Pointer
	monotone_read    func(unsafe.Pointer, *MonotoneEvent) int
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

type MonotoneEvent struct {
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

func (m *Monotone) Write(batch []MonotoneEvent) error {
	rc := monotone_write(m.env, batch, len(batch))
	if rc == -1 {
		return m.Error()
	}
	return nil
}

func (m *Monotone) Cursor(key MonotoneEvent) (*MonotoneCursor, error) {
	cursor := monotone_cursor(m.env, nil, &key)
	if cursor == nil {
		return nil, m.Error()
	}
	return &MonotoneCursor{
		monotone: m,
		cursor:   cursor,
	}, nil
}

func (m *Monotone) Execute(command string) (string, error) {
	var resultPtr unsafe.Pointer
	rc := monotone_execute(m.env, command, &resultPtr)
	if rc == -1 {
		return "", m.Error()
	}
	result := goString(&resultPtr)
	defer free(resultPtr)
	return strings.Clone(result), nil
}

func (m *Monotone) Error() error {
	return errors.New(monotone_error(m.env))
}

func (m *Monotone) Close() {
	monotone_free(unsafe.Pointer(m.env))
}

type MonotoneCursor struct {
	monotone *Monotone
	cursor   unsafe.Pointer
	total    int
}

func (m *MonotoneCursor) Read() (*MonotoneEvent, error) {
	if m.total > 0 {
		rc := monotone_next(m.cursor)
		if rc == -1 {
			return nil, m.monotone.Error()
		}
	}

	var event MonotoneEvent
	rc := monotone_read(m.cursor, &event)
	if rc == -1 {
		return nil, m.monotone.Error()
	}
	if rc == 0 {
		return nil, io.EOF
	}

	m.total++

	return &event, nil
}

func (m *MonotoneCursor) Total() int {
	return m.total
}

func (m *MonotoneCursor) Close() {
	monotone_free(unsafe.Pointer(m.cursor))
}

func goString(ptr *unsafe.Pointer) string {
	ptr2 := *ptr
	if ptr2 == nil {
		return ""
	}
	var length int
	for {
		if *(*byte)(unsafe.Add(ptr2, uintptr(length))) == '\x00' {
			break
		}
		length++
	}
	return string(unsafe.Slice((*byte)(ptr2), length))
}

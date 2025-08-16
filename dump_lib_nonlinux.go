//go:build !linux

package monotone

func dumpEmbeddedLib() (path string, closer func() error, err error) {
	panic("unsupported os (only linux)")
}

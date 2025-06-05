//go:build !linux

package monotone

func dumpEmbed() (path string, closer func() error, err error) {
	panic("unsupported os (only linux)")
}

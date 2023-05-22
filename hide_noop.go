//go:build !windows
// +build !windows

package goappupdate

func hideFile(path string) error {
	return nil
}

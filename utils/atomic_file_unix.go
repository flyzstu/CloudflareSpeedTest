//go:build !windows

package utils

import "os"

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}

func syncParentDirectory(directory string) error {
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

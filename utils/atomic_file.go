package utils

import (
	"io"
	"os"
	"path/filepath"
)

// atomicWriteFile publishes data by renaming a fully written temporary file in
// the destination directory. Readers therefore see either the previous file or
// the complete replacement, never a partially written result.
func atomicWriteFile(path string, data []byte, defaultMode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	mode := defaultMode
	if current, statErr := os.Stat(path); statErr == nil {
		mode = current.Mode().Perm()
	} else if !os.IsNotExist(statErr) {
		temporary.Close()
		return statErr
	}
	if err = temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}

	written, err := temporary.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = replaceFile(temporaryPath, path); err != nil {
		return err
	}
	return syncParentDirectory(directory)
}

//go:build windows

package utils

import "golang.org/x/sys/windows"

func replaceFile(source, destination string) error {
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPath, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		sourcePath,
		destinationPath,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

func syncParentDirectory(string) error {
	// MoveFileEx with MOVEFILE_WRITE_THROUGH flushes the move on Windows.
	return nil
}

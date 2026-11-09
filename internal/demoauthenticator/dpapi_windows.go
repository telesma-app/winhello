package demoauthenticator

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/windows"
)

// New uses Windows DPAPI to protect the given store path for the current user.
func New(path string) *Authenticator {
	return &Authenticator{path: path, protect: protect, unprotect: unprotect}
}

func protect(plaintext []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(plaintext)), Data: unsafe.SliceData(plaintext)}

	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}

	return takeDataBlob(out)
}

func unprotect(ciphertext []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(ciphertext)), Data: unsafe.SliceData(ciphertext)}

	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}

	return takeDataBlob(out)
}

func takeDataBlob(blob windows.DataBlob) ([]byte, error) {
	native := unsafe.Slice(blob.Data, blob.Size)
	data := bytes.Clone(native)
	clear(native)

	if _, err := windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data))); err != nil {
		clear(data)
		return nil, err
	}

	return data, nil
}

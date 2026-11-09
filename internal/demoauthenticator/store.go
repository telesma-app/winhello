package demoauthenticator

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
)

type storedCredential struct {
	ID         []byte                                   `cbor:"id"`
	RPID       string                                   `cbor:"rpId"`
	User       credential.PublicKeyCredentialUserEntity `cbor:"user"`
	PrivateKey []byte                                   `cbor:"privateKey"`
}

// RemoveCredential rolls back a registration that failed after the key was stored.
func (a *Authenticator) RemoveCredential(id []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	stored, err := a.readCredential()
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNoCredentials
	}

	if err != nil {
		return err
	}

	clear(stored.PrivateKey)

	if !bytes.Equal(stored.ID, id) {
		return ErrNoCredentials
	}

	if err := os.Remove(a.path); err != nil {
		return fmt.Errorf("remove credential: %w", err)
	}

	return nil
}

func (a *Authenticator) readCredential() (storedCredential, error) {
	protected, err := os.ReadFile(a.path)
	if err != nil {
		return storedCredential{}, fmt.Errorf("read credential store: %w", err)
	}

	encoded, err := a.unprotect(protected)
	if err != nil {
		return storedCredential{}, fmt.Errorf("decrypt credential: %w", err)
	}
	defer clear(encoded)

	var stored storedCredential
	if err := cbor.Unmarshal(encoded, &stored); err != nil {
		clear(stored.PrivateKey)
		return storedCredential{}, fmt.Errorf("decode credential: %w", err)
	}

	if len(stored.ID) != credentialIDSize || stored.RPID == "" || len(stored.User.ID) == 0 || len(stored.User.ID) > maxUserIDSize {
		clear(stored.PrivateKey)
		return storedCredential{}, errors.New("invalid credential store record")
	}

	return stored, nil
}

func (a *Authenticator) writeCredential(stored storedCredential) error {
	encoded, err := cbor.Marshal(stored)
	if err != nil {
		return fmt.Errorf("encode credential: %w", err)
	}
	defer clear(encoded)

	protected, err := a.protect(encoded)
	if err != nil {
		return fmt.Errorf("encrypt credential: %w", err)
	}

	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create credential store directory: %w", err)
	}

	file, err := os.CreateTemp(dir, ".credential-*")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	defer os.Remove(file.Name()) //nolint:errcheck // An abandoned temporary file contains only encrypted data.

	_, writeErr := file.Write(protected)
	if writeErr == nil {
		writeErr = file.Sync()
	}

	if err := errors.Join(writeErr, file.Close()); err != nil {
		return fmt.Errorf("write credential: %w", err)
	}

	// Publish only a complete file, without replacing a credential from another operation.
	if err := os.Link(file.Name(), a.path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrCredentialStoreFull
		}

		return fmt.Errorf("publish credential: %w", err)
	}

	return nil
}

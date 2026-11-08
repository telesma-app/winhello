package winhello

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telesma-app/ctap/credential"
	"golang.org/x/sys/windows"
)

func replaceWebAuthnProc(t *testing.T, target **windows.LazyProc, replacement *windows.LazyProc) {
	t.Helper()

	previous := *target
	*target = replacement

	t.Cleanup(func() { *target = previous })
}

type webAuthnOperationTest struct {
	name  string
	procs []**windows.LazyProc
	call  func() error
}

func webAuthnOperations(t *testing.T) []webAuthnOperationTest {
	t.Helper()

	return []webAuthnOperationTest{
		{
			name:  "GetAssertion",
			procs: []**windows.LazyProc{&procWebAuthNAuthenticatorGetAssertion, &procWebAuthNFreeAssertion},
			call: func() error {
				resp, err := GetAssertion(0, "example.org", nil, nil, nil, nil)
				assert.Nil(t, resp)

				return err
			},
		},
		{
			name:  "MakeCredential",
			procs: []**windows.LazyProc{&procWebAuthNAuthenticatorMakeCredential, &procWebAuthNFreeCredentialAttestation},
			call: func() error {
				resp, err := MakeCredential(0, nil, credential.PublicKeyCredentialRpEntity{}, credential.PublicKeyCredentialUserEntity{}, nil, nil, nil, nil)
				assert.Nil(t, resp)

				return err
			},
		},
		{
			name:  "CancelCurrentOperation",
			procs: []**windows.LazyProc{&procWebAuthNCancelCurrentOperation},
			call:  func() error { return CancelCurrentOperation(&windows.GUID{}) },
		},
		{
			name:  "DeletePlatformCredential",
			procs: []**windows.LazyProc{&procWebAuthNDeletePlatformCredential},
			call:  func() error { return DeletePlatformCredential([]byte{1}) },
		},
		{
			name:  "CancellationID",
			procs: []**windows.LazyProc{&procWebAuthNGetCancellationId},
			call: func() error {
				id, err := CancellationID()
				assert.Nil(t, id)

				return err
			},
		},
		{
			name:  "PlatformCredentialList",
			procs: []**windows.LazyProc{&procWebAuthNGetPlatformCredentialList, &procWebAuthNFreePlatformCredentialList},
			call: func() error {
				list, err := PlatformCredentialList("", false)
				assert.Nil(t, list)

				return err
			},
		},
		{
			name:  "AuthenticatorList",
			procs: []**windows.LazyProc{&procWebAuthNGetAuthenticatorList, &procWebAuthNFreeAuthenticatorList},
			call: func() error {
				list, err := AuthenticatorList()
				assert.Nil(t, list)

				return err
			},
		},
		{
			name:  "IsUserVerifyingPlatformAuthenticatorAvailable",
			procs: []**windows.LazyProc{&procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable},
			call: func() error {
				available, err := IsUserVerifyingPlatformAuthenticatorAvailable()
				assert.False(t, available)

				return err
			},
		},
	}
}

func TestUnavailableWebAuthnAPI(t *testing.T) {
	for _, tt := range []struct {
		name string
		dll  string
		want error
	}{
		{"missing_DLL", "winhello-test-unavailable.dll", windows.ERROR_MOD_NOT_FOUND},
		{"missing_version_export", "kernel32.dll", windows.ERROR_PROC_NOT_FOUND},
	} {
		t.Run(tt.name, func(t *testing.T) {
			replaceWebAuthnProc(t, &procWebAuthNGetApiVersionNumber, windows.NewLazySystemDLL(tt.dll).NewProc("WebAuthNGetApiVersionNumber"))

			// Exercise the same expression used during package initialization.
			previous := currVer

			t.Cleanup(func() { currVer = previous })

			currVer = availableVersions(APIVersionNumber())
			assert.Zero(t, APIVersionNumber())
			assert.Equal(t, currentVersion{}, *currVer)

			for _, operation := range webAuthnOperations(t) {
				err := operation.call()
				require.ErrorIs(t, err, errors.ErrUnsupported, operation.name)
				assert.ErrorIs(t, err, tt.want, operation.name)
			}

			assert.Equal(t, "HRESULT 0x80090029", ErrorName(windows.NTE_NOT_SUPPORTED))
			assert.Equal(t, windows.Handle(windows.NTE_NOT_SUPPORTED), W3CExceptionDOMError(windows.NTE_NOT_SUPPORTED))
		})
	}
}

func TestUnavailableWebAuthnExports(t *testing.T) {
	if APIVersionNumber() == 0 {
		t.Skip("Windows WebAuthn API is unavailable")
	}

	for _, operation := range webAuthnOperations(t) {
		for _, proc := range operation.procs {
			t.Run((*proc).Name, func(t *testing.T) {
				name := (*proc).Name
				replaceWebAuthnProc(t, proc, windows.NewLazySystemDLL("kernel32.dll").NewProc(name))

				err := operation.call()
				require.ErrorIs(t, err, errors.ErrUnsupported)
				assert.ErrorIs(t, err, windows.ERROR_PROC_NOT_FOUND)
				assert.ErrorContains(t, err, name)
			})
		}
	}
}

func TestUnavailableWebAuthnErrorHelpers(t *testing.T) {
	replaceWebAuthnProc(t, &procWebAuthNGetErrorName, windows.NewLazySystemDLL("kernel32.dll").NewProc("WebAuthNGetErrorName"))
	replaceWebAuthnProc(t, &procWebAuthNGetW3CExceptionDOMError, windows.NewLazySystemDLL("kernel32.dll").NewProc("WebAuthNGetW3CExceptionDOMError"))

	assert.Equal(t, "HRESULT 0x80090029", ErrorName(windows.NTE_NOT_SUPPORTED))
	assert.Equal(t, windows.Handle(windows.NTE_NOT_SUPPORTED), W3CExceptionDOMError(windows.NTE_NOT_SUPPORTED))
}

func TestMissingOptionalExportPreservesBaselineAPI(t *testing.T) {
	if APIVersionNumber() == 0 {
		t.Skip("Windows WebAuthn API is unavailable")
	}

	replaceWebAuthnProc(t, &procWebAuthNGetAuthenticatorList, windows.NewLazySystemDLL("kernel32.dll").NewProc("WebAuthNGetAuthenticatorList"))

	_, err := AuthenticatorList()
	require.ErrorIs(t, err, errors.ErrUnsupported)

	id, err := CancellationID()
	require.NoError(t, err)
	assert.NotNil(t, id)
}

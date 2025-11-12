//go:build windows

package winhello

import (
	"encoding/hex"
	"os"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
)

var clsid = "{1537ff70-8f94-495b-bad1-bcff96311d5f}"

func requirePluginTest(t *testing.T) {
	t.Helper()
	if enabled := os.Getenv("WINHELLO_PLUGIN_TESTS"); enabled != "1" && enabled != "true" {
		t.Skip("WINHELLO_PLUGIN_TESTS is not set")
	}
}

func TestAddAuthenticator(t *testing.T) {
	requirePluginTest(t)

	svg := `<?xml version="1.0" encoding="utf-8"?>
	<svg width="800px" height="800px" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
	<path fill-rule="evenodd" clip-rule="evenodd" d="M8 16L3.54223 12.3383C1.93278 11.0162 1 9.04287 1 6.96005C1 3.11612 4.15607 0 8 0C11.8439 0 15 3.11612 15 6.96005C15 9.04287 14.0672 11.0162 12.4578 12.3383L8 16ZM3 6H5C6.10457 6 7 6.89543 7 8V9L3 7.5V6ZM11 6C9.89543 6 9 6.89543 9 8V9L13 7.5V6H11Z" fill="#000000"/>
	</svg>`
	_ = svg

	//refClsid, err := windows.GUIDFromString(clsid)
	//require.NoError(t, err)

	/*callbackHandle := windows.NewCallback(registerStatusChangeCallback)
	var myContext uintptr = 12345
	var registerHandle windows.Handle

	r1, _, _ := procWebAuthNPluginRegisterStatusChangeCallback.Call(
		callbackHandle,
		myContext,
		uintptr(unsafe.Pointer(&refClsid)),
		uintptr(unsafe.Pointer(&registerHandle)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		t.Fatal(hr)
	}*/

	state, err := PluginGetAuthenticatorState(clsid)
	if err != nil {
		t.Fatal(err)
	}
	if state != PluginAuthenticatorStateEnabled {
		t.Fatal("Authenticator is not enabled")
	}

	_, err = PluginAddAuthenticator(&PluginAddAuthenticatorOptions{
		AuthenticatorName: "GoPass Manager",
		CLSID:             clsid,
		PluginRPID:        "id.krasovs.ky",
		//LightThemeLogoSvg: svg,
		//DarkThemeLogoSvg:  svg,
		AuthenticatorInfo: &protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{"FIDO_2_1", "FIDO_2_0"},
			Extensions:         []extension.ExtensionIdentifier{"prf", extension.ExtensionIdentifierHMACSecret},
			AAGUID:             uuid.MustParse("fd34cf01-7dab-462e-92f9-f66be96e599c"),
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo, protocol.PinUvAuthProtocolOne},
			Options: map[protocol.Option]bool{
				protocol.OptionResidentKeys:     true,
				protocol.OptionUserPresence:     true,
				protocol.OptionUserVerification: true,
				protocol.OptionAlwaysUv:         true,
			},
			Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportInternal},
			Algorithms: []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}},
		},
	})
	assert.NoError(t, err)

	//PluginRemoveAuthenticator(clsid)
}

func TestPluginAuthenticatorCredentials(t *testing.T) {
	requirePluginTest(t)

	err := PluginAuthenticatorAddCredentials(clsid, []*PluginCredentialDetail{
		{
			CredentialID:    []byte("1234567890"),
			RPID:            "id.krasovs.ky",
			RPName:          "GoPass Manager",
			UserID:          []byte("savely"),
			UserName:        "savely",
			UserDisplayName: "Savely",
		},
	})
	assert.NoError(t, err)

	credentials, err := PluginAuthenticatorGetAllCredentials(clsid)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, credentials)

	assert.Equal(t, "1234567890", string(credentials[0].CredentialID))

	err = PluginAuthenticatorRemoveCredentials(clsid, []*PluginCredentialDetail{
		{CredentialID: []byte("1234567890")},
	})
	assert.NoError(t, err)

	err = PluginAuthenticatorAddCredentials(clsid, []*PluginCredentialDetail{
		{
			CredentialID:    []byte("1234567890"),
			RPID:            "id.krasovs.ky",
			RPName:          "GoPass Manager",
			UserID:          []byte("savely"),
			UserName:        "savely",
			UserDisplayName: "Savely",
		},
	})
	assert.NoError(t, err)

	credentials, err = PluginAuthenticatorGetAllCredentials(clsid)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, credentials)

	assert.Equal(t, "1234567890", string(credentials[0].CredentialID))

	err = PluginAuthenticatorRemoveAllCredentials(clsid)
	assert.NoError(t, err)
}

func TestPluginPerformUserVerification(t *testing.T) {
	requirePluginTest(t)

	_, err := PluginPerformUserVerification(&PluginUserVerificationRequestOptions{
		WindowHandle:  0,
		TransactionID: clsid,
		Username:      "",
		DisplayHint:   "",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPluginGetUserVerificationCount(t *testing.T) {
	requirePluginTest(t)

	count, err := PluginGetUserVerificationCount(clsid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Greater(t, count, uint32(0))
}

func TestPluginGetUserVerificationPublicKey(t *testing.T) {
	requirePluginTest(t)

	pubKey, err := PluginGetUserVerificationPublicKey(clsid)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, pubKey)
}

func TestPluginGetOperationSigningPublicKey(t *testing.T) {
	requirePluginTest(t)

	pubKey, err := PluginGetOperationSigningPublicKey(clsid)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, pubKey)
}

func TestPluginEncodeMakeCredentialResponse(t *testing.T) {
	requirePluginTest(t)

	b, err := hex.DecodeString("13d2cbaa54c70765984a2c06e961c05dbebc030509adb7f9b24fe39518885faa45000033b3eabb46cce24180bfae9e96fa6d2975cf006008172df33bb4e0a992eb2294d5f7d022f475f4429c4c2945707c9c0de078ea201a0fb90f30be44d93c808267f3b506fbcafb76293ce7fcb47c2488bfe1d0fc214734811d5e6a0bc901766f953e8e70ae1ae3ae647c88a4f3fe2cdd801b71d48ea50102032620012158206d21de7d8f97ea995b9163b190150c20b4f9b98ab622893cffbf896b217eba392258208e260991d7cdbf6f6dbb36dc718fab30bdfaa9aff33c30b5068f1822e33bf75e")
	if err != nil {
		t.Fatal(err)
	}

	encodedResponse, err := PluginEncodeMakeCredentialResponse(&WinHelloMakeCredentialResponse{
		AuthenticatorMakeCredentialResponse: &protocol.AuthenticatorMakeCredentialResponse{
			AuthDataRaw: b,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, encodedResponse)
}

//go:build windows

package main

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"

	"github.com/goforj/godump"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/winhello"
	"github.com/telesma-app/winhello/hiddenwindow"
)

func main() {
	wnd, err := hiddenwindow.New(slog.New(slog.DiscardHandler), "WinHello Example")
	if err != nil {
		panic(err)
	}
	defer wnd.Close()

	// This local API demo uses placeholder client data. A real relying party
	// must supply clientDataJSON with its challenge and validate both responses.
	slog.Info("Creating a passkey with Windows Hello")

	created, err := winhello.MakeCredential(
		wnd.WindowHandle(),
		[]byte("{}"),
		credential.PublicKeyCredentialRpEntity{
			ID:   "example.org",
			Name: "WinHello Example",
		},
		credential.PublicKeyCredentialUserEntity{
			ID:          []byte(rand.Text()),
			Name:        "winhello-example",
			DisplayName: "WinHello Example",
		},
		[]credential.PublicKeyCredentialParameters{
			{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			},
		},
		nil,
		nil,
		&winhello.AuthenticatorMakeCredentialOptions{
			AuthenticatorAttachment:         winhello.WinHelloAuthenticatorAttachmentPlatform,
			RequireResidentKey:              true,
			UserVerificationRequirement:     winhello.WinHelloUserVerificationRequirementRequired,
			AttestationConveyancePreference: winhello.WinHelloAttestationConveyancePreferenceNone,
		},
	)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := winhello.DeletePlatformCredential(created.CredentialID); err != nil {
			slog.Error("Failed to delete the demo passkey", "err", err)
		} else {
			slog.Info("Deleted the demo passkey")
		}
	}()

	slog.Info("Created passkey", "residentKey", created.ResidentKey, "transport", created.UsedTransport,
		"credentialID", base64.RawURLEncoding.EncodeToString(created.CredentialID))
	slog.Info("Using the created passkey with Windows Hello")

	assertion, err := winhello.GetAssertion(
		wnd.WindowHandle(),
		"example.org",
		[]byte("{}"),
		[]credential.PublicKeyCredentialDescriptor{
			{
				ID:   created.CredentialID,
				Type: credential.PublicKeyCredentialTypePublicKey,
			},
		},
		nil,
		&winhello.AuthenticatorGetAssertionOptions{
			AuthenticatorAttachment:     winhello.WinHelloAuthenticatorAttachmentPlatform,
			UserVerificationRequirement: winhello.WinHelloUserVerificationRequirementRequired,
			CredentialHints: []credential.PublicKeyCredentialHint{
				credential.PublicKeyCredentialHintClientDevice,
			},
		},
	)
	if err != nil {
		panic(err)
	}

	godump.Dump(assertion)
}

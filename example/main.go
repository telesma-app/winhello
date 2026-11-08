//go:build windows

package main

import (
	"encoding/base64"
	"log/slog"

	"github.com/go-ctap/winhello"
	"github.com/go-ctap/winhello/hiddenwindow"
	"github.com/goforj/godump"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/webauthn"
)

func main() {
	wnd, err := hiddenwindow.New(slog.New(slog.DiscardHandler), "WinHello Example")
	if err != nil {
		panic(err)
	}
	defer wnd.Close()

	credIDStr := "ruDDeY_rT2Jv25HOJCY5LhTUXlX1DrIaAYVTXrumUtU5qNvr9uo77UekHDMiu1TEIRgw20ptOx841RsVZl--iofFQXkc0vIZ0-gpXZtw5g138QI0a1d4WBQbF7F1PbpC"

	credID, err := base64.RawURLEncoding.DecodeString(credIDStr)
	if err != nil {
		panic(err)
	}

	assertion, err := winhello.GetAssertion(
		wnd.WindowHandle(),
		"example.org",
		[]byte("{}"),
		[]credential.PublicKeyCredentialDescriptor{
			{
				ID:   credID,
				Type: credential.PublicKeyCredentialTypePublicKey,
			},
		},
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
						credIDStr: {
							First: []byte("first"),
						},
					},
				},
			},
		},
		&winhello.AuthenticatorGetAssertionOptions{
			AuthenticatorAttachment:     winhello.WinHelloAuthenticatorAttachmentCrossPlatform,
			UserVerificationRequirement: winhello.WinHelloUserVerificationRequirementDiscouraged,
			CredentialHints: []credential.PublicKeyCredentialHint{
				credential.PublicKeyCredentialHintSecurityKey,
			},
		},
	)
	if err != nil {
		panic(err)
	}

	godump.Dump(assertion)
}

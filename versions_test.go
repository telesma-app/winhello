package winhello

import (
	"fmt"
	"testing"
)

func TestAvailableVersions(t *testing.T) {
	// Structure versions from microsoft/webauthn's API version table.
	for _, tt := range []struct {
		api                                          uint32
		makeOptions, getOptions, attestation         uint32
		assertion, credentialDetails, getCredentials uint32
		authenticatorDetails                         uint32
	}{
		{1, 3, 4, 3, 1, 0, 0, 0},
		{2, 3, 4, 3, 1, 0, 0, 0},
		{3, 4, 5, 4, 2, 0, 0, 0},
		{4, 5, 6, 4, 3, 1, 1, 0},
		{5, 5, 6, 4, 3, 2, 1, 0},
		{6, 6, 6, 5, 4, 2, 1, 0},
		{7, 7, 7, 6, 5, 2, 1, 0},
		{8, 8, 8, 7, 5, 3, 1, 0},
		{9, 9, 9, 8, 6, 4, 1, 1},
		{10, 9, 9, 8, 6, 4, 1, 1},
	} {
		t.Run(fmt.Sprintf("API_%d", tt.api), func(t *testing.T) {
			want := currentVersion{
				rpEntityInformation: 1, userEntityInformation: 1, clientData: 1,
				coseCredentialParameter: 1, credential: 1, credentialEx: 1,
				commonAttestation:                  1,
				authenticatorMakeCredentialOptions: tt.makeOptions,
				authenticatorGetAssertionOptions:   tt.getOptions,
				credentialAttestation:              tt.attestation,
				assertion:                          tt.assertion,
				credentialDetails:                  tt.credentialDetails,
				getCredentialsOptions:              tt.getCredentials,
				authenticatorDetails:               tt.authenticatorDetails,
			}
			if got := *availableVersions(tt.api); got != want {
				t.Errorf("availableVersions(%d) = %+v, want %+v", tt.api, got, want)
			}
		})
	}
}

func TestUnavailableAPIVersions(t *testing.T) {
	if got := *availableVersions(0); got != (currentVersion{}) {
		t.Errorf("unavailable API must not advertise structure versions: %+v", got)
	}
}

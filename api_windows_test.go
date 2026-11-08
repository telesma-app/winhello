package winhello

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWebAuthnQueries(t *testing.T) {
	assert.GreaterOrEqual(t, APIVersionNumber(), uint32(1))
	_, err := IsUserVerifyingPlatformAuthenticatorAvailable()
	require.NoError(t, err)
	assert.Equal(t, "Success", ErrorName(windows.S_OK))
	assert.Equal(t, windows.Handle(windows.S_OK), W3CExceptionDOMError(windows.S_OK))

	id, err := CancellationID()
	require.NoError(t, err)
	assert.NotEqual(t, windows.GUID{}, *id)
}

//go:build !windows

package demoauthenticator

func testAuthenticator(path string) *Authenticator {
	identity := func(data []byte) ([]byte, error) { return data, nil }
	return &Authenticator{path: path, protect: identity, unprotect: identity}
}

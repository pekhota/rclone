package webdav

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// challenge401 makes the 401 an unauthenticated request to rawURL would get
// from a server offering digest authentication with the nonce given
func challenge401(t *testing.T, rawURL, nonce string) *http.Response {
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	header := http.Header{}
	header.Set("WWW-Authenticate", `Digest realm="test", nonce="`+nonce+`", algorithm=MD5, qop="auth"`)
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     header,
		Request:    &http.Request{URL: u, Header: http.Header{}},
	}
}

// signPath returns the Authorization header f would put on a request for path
func signPath(t *testing.T, f *Fs, path string) string {
	req, err := http.NewRequest("PROPFIND", "http://example.com"+path, nil)
	require.NoError(t, err)
	authorization, err := f.digestAuthorization(req)
	require.NoError(t, err)
	return authorization
}

// TestDigestNonceCount checks the nonce count increases for every request
// signed with a nonce, and restarts when the nonce changes.
//
// The count is the replay protection in digest authentication, so a server
// which keeps a nonce alive across requests rejects a repeated count.
func TestDigestNonceCount(t *testing.T) {
	f := &Fs{}
	f.opt.User = "alice"
	f.opt.Pass = "secret"

	require.True(t, f.setDigestChallenge(challenge401(t, "http://example.com/", "nonce-1")))
	first := signPath(t, f, "/a")

	// The same nonce is offered again, which is what happens when another
	// request was in flight and got challenged too
	require.True(t, f.setDigestChallenge(challenge401(t, "http://example.com/", "nonce-1")))
	second := signPath(t, f, "/b")

	assert.True(t, strings.Contains(first, "nc=00000001"), first)
	assert.True(t, strings.Contains(second, "nc=00000002"), second)

	// A new nonce restarts the count
	require.True(t, f.setDigestChallenge(challenge401(t, "http://example.com/", "nonce-2")))
	third := signPath(t, f, "/c")
	assert.True(t, strings.Contains(third, "nc=00000001"), third)
}

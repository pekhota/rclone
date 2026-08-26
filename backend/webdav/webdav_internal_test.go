package webdav_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	auth "github.com/abbot/go-http-auth"
	"github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/backend/webdav"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configfile"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xwebdav "golang.org/x/net/webdav"
)

var (
	remoteName = "TestWebDAV"
	headers    = []string{"X-Potato", "sausage", "X-Rhubarb", "cucumber"}
)

// prepareServer the test server and return a function to tidy it up afterwards
// with each request the headers option tests are executed
func prepareServer(t *testing.T) (configmap.Simple, func()) {
	// test the headers are there send send a dummy response to About
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		what := fmt.Sprintf("%s %s: Header ", r.Method, r.URL.Path)
		assert.Equal(t, headers[1], r.Header.Get(headers[0]), what+headers[0])
		assert.Equal(t, headers[3], r.Header.Get(headers[2]), what+headers[2])
		_, err := fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
<d:response>
 <d:href>/remote.php/webdav/</d:href>
 <d:propstat>
  <d:prop>
   <d:quota-available-bytes>-3</d:quota-available-bytes>
   <d:quota-used-bytes>376461895</d:quota-used-bytes>
  </d:prop>
  <d:status>HTTP/1.1 200 OK</d:status>
 </d:propstat>
</d:response>
</d:multistatus>`)
		require.NoError(t, err)
	})
	// Make the test server
	ts := httptest.NewServer(handler)

	// Configure the remote
	configfile.Install()

	m := configmap.Simple{
		"type": "webdav",
		"url":  ts.URL,
		// add headers to test the headers option
		"headers": strings.Join(headers, ","),
	}

	// return a function to tidy up
	return m, ts.Close
}

// prepare the test server and return a function to tidy it up afterwards
func prepare(t *testing.T) (fs.Fs, func()) {
	m, tidy := prepareServer(t)

	// Instantiate the WebDAV server
	f, err := webdav.NewFs(context.Background(), remoteName, "", m)
	require.NoError(t, err)

	return f, tidy
}

// TestHeaders any request will test the headers option
func TestHeaders(t *testing.T) {
	f, tidy := prepare(t)
	defer tidy()

	// send an About response since that is all the dummy server can return
	_, err := f.Features().About(context.Background())
	require.NoError(t, err)
}

// TestListAllAuthRedirect checks auth_redirect is honoured on listAll PROPFIND.
func TestListAllAuthRedirect(t *testing.T) {
	var targetAuth string
	var targetHits int

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		targetAuth = r.Header.Get("Authorization")
		_, err := fmt.Fprint(w, `<d:multistatus xmlns:d="DAV:"></d:multistatus>`)
		require.NoError(t, err)
	}))
	defer target.Close()

	// Redirect via a different hostname so net/http strips Authorization on cross-host redirect.
	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	configfile.Install()
	m := configmap.Simple{
		"type":          "webdav",
		"url":           source.URL,
		"user":          "alice",
		"pass":          obscure.MustObscure("secret"),
		"auth_redirect": "true",
	}

	f, err := webdav.NewFs(context.Background(), remoteName, "", m)
	require.NoError(t, err)

	_, _ = f.List(context.Background(), "")

	assert.GreaterOrEqual(t, targetHits, 1, "redirect target should receive the request")
	assert.NotEmpty(t, targetAuth, "Authorization header should be preserved across redirect")
}

// TestReservedCharactersInPathAreEscaped verifies that reserved characters
// like semicolons and equals signs in file paths are percent-encoded in
// HTTP requests to the WebDAV server (RFC 3986 compliance).
func TestReservedCharactersInPathAreEscaped(t *testing.T) {
	var capturedPath string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.RequestURI
		// Return a 404 so the NewObject call fails cleanly
		w.WriteHeader(http.StatusNotFound)
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	configfile.Install()
	m := configmap.Simple{
		"type": "webdav",
		"url":  ts.URL,
	}

	f, err := webdav.NewFs(context.Background(), remoteName, "", m)
	require.NoError(t, err)

	// Try to access a file with a semicolon in the name.
	// We expect the request to fail (404), but the path should be escaped.
	_, _ = f.NewObject(context.Background(), "my;test")

	// The semicolon must be percent-encoded as %3B
	assert.Contains(t, capturedPath, "my%3Btest", "semicolons in path should be percent-encoded")
	assert.NotContains(t, capturedPath, "my;test", "raw semicolons should not appear in path")
}

const fileInfoResponse = `<d:multistatus xmlns:d="DAV:">
<d:response>
 <d:href>/file.txt</d:href>
 <d:propstat>
  <d:prop>
   <d:getcontentlength>10</d:getcontentlength>
   <d:resourcetype/>
  </d:prop>
  <d:status>HTTP/1.1 200 OK</d:status>
 </d:propstat>
</d:response>
</d:multistatus>`

func prepareFileObject(ctx context.Context, t *testing.T, getHandler http.HandlerFunc) (fs.Object, func()) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PROPFIND" {
			w.WriteHeader(http.StatusMultiStatus)
			_, err := fmt.Fprint(w, fileInfoResponse)
			require.NoError(t, err)
			return
		}
		if r.Method == http.MethodGet {
			getHandler(w, r)
			return
		}
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	})
	ts := httptest.NewServer(handler)

	configfile.Install()
	f, err := webdav.NewFs(ctx, remoteName, "", configmap.Simple{
		"type": "webdav",
		"url":  ts.URL,
	})
	require.NoError(t, err)
	o, err := f.NewObject(ctx, "file.txt")
	require.NoError(t, err)
	return o, ts.Close
}

func TestOpenDoesNotRetryIgnoredRange(t *testing.T) {
	var getRequests atomic.Int32
	o, tidy := prepareFileObject(context.Background(), t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "bytes=2-4", r.Header.Get("Range"))
		getRequests.Add(1)
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		_, err := io.WriteString(w, "abcdefghij")
		require.NoError(t, err)
	})
	defer tidy()

	in, err := o.Open(context.Background(), &fs.RangeOption{Start: 2, End: 4})
	assert.Nil(t, in)
	assert.ErrorIs(t, err, fs.ErrorRangeIgnored)
	assert.Equal(t, int32(1), getRequests.Load())
}

func TestOpenRetriesMismatchedContentRange(t *testing.T) {
	var getRequests atomic.Int32
	o, tidy := prepareFileObject(context.Background(), t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "bytes=2-4", r.Header.Get("Range"))
		if getRequests.Add(1) == 1 {
			w.Header().Set("Content-Length", "3")
			w.Header().Set("Content-Range", "bytes 0-2/10")
			w.WriteHeader(http.StatusPartialContent)
			_, err := io.WriteString(w, "abc")
			require.NoError(t, err)
			return
		}
		w.Header().Set("Content-Length", "3")
		w.Header().Set("Content-Range", "bytes 2-4/10")
		w.WriteHeader(http.StatusPartialContent)
		_, err := io.WriteString(w, "cde")
		require.NoError(t, err)
	})
	defer tidy()

	in, err := o.Open(context.Background(), &fs.RangeOption{Start: 2, End: 4})
	require.NoError(t, err)
	defer func() { require.NoError(t, in.Close()) }()
	contents, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, "cde", string(contents))
	assert.Equal(t, int32(2), getRequests.Load())
}

func TestCopyFallsBackWhenRangeIgnored(t *testing.T) {
	var rangeRequests atomic.Int32
	var fullRequests atomic.Int32
	ctx, ci := fs.AddConfig(context.Background())
	ci.LowLevelRetries = 2
	ci.MultiThreadStreams = 2
	ci.MultiThreadSet = true
	ci.MultiThreadCutoff = 1
	ci.MultiThreadChunkSize = 4

	src, tidy := prepareFileObject(ctx, t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			fullRequests.Add(1)
		} else {
			rangeRequests.Add(1)
		}
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		_, err := io.WriteString(w, "abcdefghij")
		require.NoError(t, err)
	})
	defer tidy()

	dstFs, err := local.NewFs(ctx, "local", t.TempDir(), configmap.Simple{
		"no_preallocate": "true",
		"no_sparse":      "true",
	})
	require.NoError(t, err)
	dst, err := operations.Copy(ctx, dstFs, nil, "file.txt", src)
	require.NoError(t, err)

	in, err := dst.Open(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, in.Close()) }()
	contents, err := io.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, "abcdefghij", string(contents))
	assert.Positive(t, rangeRequests.Load())
	assert.LessOrEqual(t, rangeRequests.Load(), int32(3))
	assert.Equal(t, int32(1), fullRequests.Load())
}

const (
	digestRealm = "rclone-test"
	digestUser  = "alice"
	digestPass  = "secret"
)

// digestServer runs a WebDAV server on dir which accepts digest
// authentication only.
func digestServer(t *testing.T, dir string) *httptest.Server {
	dav := &xwebdav.Handler{
		FileSystem: xwebdav.Dir(dir),
		LockSystem: xwebdav.NewMemLS(),
	}
	authenticator := auth.NewDigestAuthenticator(digestRealm, func(user, realm string) string {
		if user != digestUser || realm != digestRealm {
			return ""
		}
		// digest secrets are HA1, i.e. MD5(user:realm:password)
		ha1 := md5.Sum([]byte(digestUser + ":" + digestRealm + ":" + digestPass))
		return hex.EncodeToString(ha1[:])
	})
	ts := httptest.NewServer(authenticator.JustCheck(dav.ServeHTTP))
	t.Cleanup(ts.Close)
	return ts
}

// TestDigestAuth checks that a server which only accepts digest
// authentication can be listed.
func TestDigestAuth(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("0123456789"), 0600))
	ts := digestServer(t, dir)

	configfile.Install()
	f, err := webdav.NewFs(context.Background(), remoteName, "", configmap.Simple{
		"type": "webdav",
		"url":  ts.URL,
		"user": digestUser,
		"pass": obscure.MustObscure(digestPass),
	})
	require.NoError(t, err)

	entries, err := f.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "existing.txt", entries[0].Remote())
}

// TestDigestAuthStaleNonce checks that a request signed with an expired
// nonce is signed again with the replacement the server sends.
func TestDigestAuthStaleNonce(t *testing.T) {
	var mu sync.Mutex
	var schemes []string
	var digestRequests int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := "none"
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			scheme = strings.SplitN(authorization, " ", 2)[0]
		}
		mu.Lock()
		schemes = append(schemes, scheme)
		if scheme == "Digest" {
			digestRequests++
		}
		n := digestRequests
		mu.Unlock()

		// Reject the first digest attempt as stale, then accept
		if scheme != "Digest" || n == 1 {
			stale := ""
			if scheme == "Digest" {
				stale = `, stale=true`
			}
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm=%q, nonce="nonce-%d", algorithm=MD5, qop="auth"%s`, digestRealm, n, stale))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusMultiStatus)
		_, err := fmt.Fprint(w, `<d:multistatus xmlns:d="DAV:"></d:multistatus>`)
		require.NoError(t, err)
	}))
	defer ts.Close()

	configfile.Install()
	f, err := webdav.NewFs(context.Background(), remoteName, "", configmap.Simple{
		"type": "webdav",
		"url":  ts.URL,
		"user": digestUser,
		"pass": obscure.MustObscure(digestPass),
	})
	require.NoError(t, err)

	_, err = f.List(context.Background(), "")
	require.NoError(t, err)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"Basic", "Digest", "Digest"}, schemes)
}

// TestDigestAuthConfigured checks that a remote configured for digest
// doesn't send the password using basic authentication.
func TestDigestAuthConfigured(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("0123456789"), 0600))

	var mu sync.Mutex
	var schemes []string
	dav := digestServer(t, dir)
	// Record the scheme of every request, including the ones the digest
	// authenticator rejects before the handler sees them
	recorded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := "none"
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			scheme = strings.SplitN(authorization, " ", 2)[0]
		}
		mu.Lock()
		schemes = append(schemes, scheme)
		mu.Unlock()
		dav.Config.Handler.ServeHTTP(w, r)
	}))
	defer recorded.Close()

	configfile.Install()
	f, err := webdav.NewFs(context.Background(), remoteName, "", configmap.Simple{
		"type":   "webdav",
		"url":    recorded.URL,
		"user":   digestUser,
		"pass":   obscure.MustObscure(digestPass),
		"digest": "true",
	})
	require.NoError(t, err)

	entries, err := f.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, schemes)
	assert.Equal(t, "none", schemes[0], "the challenge request must not carry credentials")
	assert.NotContains(t, schemes, "Basic", "the password must never be sent using basic auth")
}

// TestDigestAuthRemembered checks that discovering digest authentication
// records it in the config, so later sessions don't send the password
// using basic authentication.
func TestDigestAuthRemembered(t *testing.T) {
	ts := digestServer(t, t.TempDir())

	configfile.Install()
	m := configmap.Simple{
		"type": "webdav",
		"url":  ts.URL,
		"user": digestUser,
		"pass": obscure.MustObscure(digestPass),
	}
	f, err := webdav.NewFs(context.Background(), remoteName, "", m)
	require.NoError(t, err)
	_, ok := m.Get("digest")
	require.False(t, ok, "digest should not be set before anything is asked of the server")

	_, err = f.List(context.Background(), "")
	require.NoError(t, err)

	digest, ok := m.Get("digest")
	assert.True(t, ok, "digest should have been written to the config")
	assert.Equal(t, "true", digest)
}

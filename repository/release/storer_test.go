// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

// fakeEnvelope is a minimal attestation.Envelope for exercising Store. Only its
// JSON marshaling matters; Store never calls the interface methods.
type fakeEnvelope struct {
	Payload string `json:"payload"`
}

func (fakeEnvelope) GetStatement() attestation.Statement       { return nil }
func (fakeEnvelope) GetPredicate() attestation.Predicate       { return nil }
func (fakeEnvelope) GetSignatures() []attestation.Signature    { return nil }
func (fakeEnvelope) GetCertificate() attestation.Certificate   { return nil }
func (fakeEnvelope) GetVerification() attestation.Verification { return nil }
func (fakeEnvelope) Verify(...any) error                       { return nil }

func testCollector(serverURL string) *Collector {
	return &Collector{
		Options: Options{
			RepoURL: "https://github.com/example/repo",
			Tag:     "v1.0.0",
			Token:   "s3cr3t",
		},
		apiBaseURL:     serverURL,
		uploadsBaseURL: serverURL,
	}
}

// writeReleaseID responds with a release lookup payload. t.Errorf is safe to
// call from the server's goroutine (unlike t.Fatal).
func writeReleaseID(t *testing.T, w http.ResponseWriter, id int64) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(map[string]any{"id": id}); err != nil {
		t.Errorf("encoding release response: %v", err)
	}
}

func TestStore(t *testing.T) {
	t.Run("uploads-each-envelope", func(t *testing.T) {
		var mu sync.Mutex
		uploads := map[string][]byte{}
		var relAuth, uploadContentType string

		mux := http.NewServeMux()
		mux.HandleFunc("GET /repos/example/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
			relAuth = r.Header.Get("Authorization")
			writeReleaseID(t, w, 4242)
		})
		mux.HandleFunc("POST /repos/example/repo/releases/4242/assets", func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading upload body: %v", err)
			}
			mu.Lock()
			uploads[r.URL.Query().Get("name")] = body
			uploadContentType = r.Header.Get("Content-Type")
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		err := testCollector(srv.URL).Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{
			fakeEnvelope{Payload: "one"},
			fakeEnvelope{Payload: "two"},
		})
		require.NoError(t, err)

		require.Equal(t, "Bearer s3cr3t", relAuth)
		require.Equal(t, "application/json", uploadContentType)
		require.Len(t, uploads, 2)
		for name, body := range uploads {
			require.True(t, strings.HasPrefix(name, "attestation-"), "unexpected asset name %q", name)
			require.True(t, strings.HasSuffix(name, ".json"), "unexpected asset name %q", name)
			require.Contains(t, string(body), `"payload"`)
		}
	})

	t.Run("errors-without-token", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GH_TOKEN", "")
		c := testCollector("http://127.0.0.1:0")
		c.Options.Token = ""
		err := c.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{fakeEnvelope{}})
		require.ErrorContains(t, err, "token is required")
	})

	t.Run("noop-on-empty", func(t *testing.T) {
		require.NoError(t, testCollector("http://127.0.0.1:0").Store(
			context.Background(), attestation.StoreOptions{}, nil,
		))
	})

	t.Run("existing-asset-is-idempotent", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /repos/example/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
			writeReleaseID(t, w, 4242)
		})
		mux.HandleFunc("POST /repos/example/repo/releases/4242/assets", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"message":"Validation Failed","errors":[{"code":"already_exists"}]}`, http.StatusUnprocessableEntity)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		err := testCollector(srv.URL).Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{fakeEnvelope{Payload: "x"}})
		require.NoError(t, err)
	})

	t.Run("retries-transient-upload-error", func(t *testing.T) {
		var attempts atomic.Int32
		mux := http.NewServeMux()
		mux.HandleFunc("GET /repos/example/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
			writeReleaseID(t, w, 4242)
		})
		mux.HandleFunc("POST /repos/example/repo/releases/4242/assets", func(w http.ResponseWriter, _ *http.Request) {
			if attempts.Add(1) == 1 {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		c := testCollector(srv.URL)
		c.Options.Retries = 3
		require.NoError(t, c.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{fakeEnvelope{Payload: "x"}}))
		require.Equal(t, int32(2), attempts.Load())
	})
}

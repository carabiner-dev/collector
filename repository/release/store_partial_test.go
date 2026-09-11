// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/internal/envtest"
	"github.com/carabiner-dev/collector/repository"
)

func TestStoreKeepsUploadingAfterFailures(t *testing.T) {
	var mu sync.Mutex
	uploads := 0

	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/example/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeReleaseID(t, w, 4243)
	})
	mux.HandleFunc("POST /repos/example/repo/releases/4243/assets", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading upload body: %v", err)
		}
		// The server rejects one of the envelopes
		if strings.Contains(string(body), `"rejected"`) {
			http.Error(w, `{"message":"Bad Request"}`, http.StatusBadRequest)
			return
		}
		mu.Lock()
		uploads++
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := testCollector(srv.URL).Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{
		fakeEnvelope{Payload: "one"},
		fakeEnvelope{Payload: "rejected"},
		envtest.Unserializable{},
		fakeEnvelope{Payload: "two"},
	})

	var serr *repository.StoreError
	require.ErrorAs(t, err, &serr)
	require.Equal(t, 2, serr.Stored)
	require.Equal(t, 2, uploads, "the envelopes after a failure must still be uploaded")
	require.Len(t, serr.Failed, 2)
	require.ErrorContains(t, serr.Failed[1], "400")
	require.ErrorIs(t, serr.Failed[2], envtest.ErrUnserializable)
	require.False(t, serr.AllFailed())
}

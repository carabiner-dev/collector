// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/olareg/olareg"
	olaregconfig "github.com/olareg/olareg/config"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/envelope/dsse"
)

func startTestRegistry(t *testing.T) string {
	t.Helper()
	srv := olareg.New(olaregconfig.Config{
		Storage: olaregconfig.ConfigStorage{
			StoreType: olaregconfig.StoreMem,
		},
	})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() {
		ts.Close()
		if err := srv.Close(); err != nil {
			t.Logf("closing olareg: %v", err)
		}
	})
	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)
	return tsURL.Host
}

// pushEmptySubject pushes a minimal empty image to ref so the registry has a
// subject for the .att tag to point at, and returns its digest in
// `sha256:<hex>` form.
func pushEmptySubject(t *testing.T, ctx context.Context, ref string) string {
	t.Helper()
	require.NoError(t, crane.Push(empty.Image, ref, crane.WithContext(ctx), crane.Insecure))
	d, err := crane.Digest(ref, crane.WithContext(ctx), crane.Insecure)
	require.NoError(t, err)
	return d
}

// validIntotoPayload builds a tiny valid in-toto statement so the round-trip
// fetch path can produce a non-nil Statement.
func validIntotoPayload() []byte {
	return []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://example.com/test/v1","subject":[{"name":"x","digest":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],"predicate":{}}`)
}

func makeDSSEEnvelope() *dsse.Envelope {
	return &dsse.Envelope{
		Envelope: &protodsse.Envelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     validIntotoPayload(),
			Signatures: []*protodsse.Signature{
				{Keyid: "k", Sig: []byte("sig")},
			},
		},
	}
}

func TestStoreRoundTripPlainDSSE(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/dsse:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	env := makeDSSEEnvelope()
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{env}))

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.NotNil(t, atts[0].GetStatement())
}

func TestStoreAppendsToExistingAttestationImage(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/append:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	// First write.
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{makeDSSEEnvelope()}))
	// Second write — must preserve the first and append the second.
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{makeDSSEEnvelope()}))

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 2, "appending should preserve prior layers")
}

func TestStoreRoundTripBundleWithCosignAnnotations(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/bundle:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	mt, err := sbundle.MediaTypeString("v0.3")
	require.NoError(t, err)

	// Build a bundle envelope with sigstore verification material so the
	// storer must hoist it into cosign layer annotations and the fetcher must
	// re-parse it back into a bundle on read.
	fakeCert := []byte{0x30, 0x82, 0x01, 0x0a} // not a real cert; only used to round-trip RawBytes
	logIDBytes := []byte{0xab, 0xcd, 0xef}
	setBytes := []byte("signed-entry-timestamp")
	canonicalBody := []byte(`{"kind":"hashedrekord","apiVersion":"0.0.1"}`)
	tsDER := []byte("rfc3161-der-bytes")

	bun := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			MediaType: mt,
			Content: &protobundle.Bundle_DsseEnvelope{
				DsseEnvelope: &protodsse.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     validIntotoPayload(),
					Signatures: []*protodsse.Signature{
						{Keyid: "k", Sig: []byte("sig")},
					},
				},
			},
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{{RawBytes: fakeCert}},
					},
				},
				TlogEntries: []*protorekor.TransparencyLogEntry{{
					LogIndex:          42,
					LogId:             &protocommon.LogId{KeyId: logIDBytes},
					IntegratedTime:    1700000000,
					InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: setBytes},
					CanonicalizedBody: canonicalBody,
				}},
				TimestampVerificationData: &protobundle.TimestampVerificationData{
					Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
						{SignedTimestamp: tsDER},
					},
				},
			},
		},
	}

	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{bun}))

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)

	got, ok := atts[0].(*bundle.Envelope)
	require.True(t, ok, "fetched envelope should be a bundle.Envelope since cosign annotations were preserved")

	// Cert chain round-tripped.
	chain := got.Bundle.GetVerificationMaterial().GetX509CertificateChain()
	require.NotNil(t, chain)
	require.Len(t, chain.GetCertificates(), 1)
	require.Equal(t, fakeCert, chain.GetCertificates()[0].GetRawBytes())

	// Tlog entry round-tripped — the fetch path repopulates LogIndex,
	// IntegratedTime, LogId, SignedEntryTimestamp, and CanonicalizedBody.
	tlogs := got.Bundle.GetVerificationMaterial().GetTlogEntries()
	require.Len(t, tlogs, 1)
	require.EqualValues(t, 42, tlogs[0].GetLogIndex())
	require.EqualValues(t, 1700000000, tlogs[0].GetIntegratedTime())
	require.Equal(t, logIDBytes, tlogs[0].GetLogId().GetKeyId())
	require.Equal(t, setBytes, tlogs[0].GetInclusionPromise().GetSignedEntryTimestamp())
	require.Equal(t, canonicalBody, tlogs[0].GetCanonicalizedBody())

	// RFC3161 timestamp round-tripped.
	ts := got.Bundle.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps()
	require.Len(t, ts, 1)
	require.Equal(t, tsDER, ts[0].GetSignedTimestamp())
}

func TestStoreEmptyEnvelopesIsNoop(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/empty:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, nil))
}

func TestCosignAnnotationsFromMaterialNil(t *testing.T) {
	t.Parallel()
	ann, err := cosignAnnotationsFromMaterial(nil)
	require.NoError(t, err)
	require.Nil(t, ann)
}

func TestCosignAnnotationsFromMaterialShapes(t *testing.T) {
	t.Parallel()
	logID := []byte{0x01, 0x02}
	mat := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: []byte("cert")}},
			},
		},
		TlogEntries: []*protorekor.TransparencyLogEntry{{
			LogIndex:          7,
			LogId:             &protocommon.LogId{KeyId: logID},
			IntegratedTime:    12345,
			InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: []byte("set")},
			CanonicalizedBody: []byte("body"),
		}},
		TimestampVerificationData: &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
				{SignedTimestamp: []byte("ts")},
			},
		},
	}

	ann, err := cosignAnnotationsFromMaterial(mat)
	require.NoError(t, err)

	// Certificate is PEM-encoded.
	certPEM := ann["dev.sigstore.cosign/certificate"]
	require.NotEmpty(t, certPEM)
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)
	require.Equal(t, []byte("cert"), block.Bytes)

	// Bundle annotation has the right shape.
	bundleJSON := ann["dev.sigstore.cosign/bundle"]
	require.NotEmpty(t, bundleJSON)
	var b struct {
		Payload struct {
			Body           string `json:"body"`
			IntegratedTime int64  `json:"integratedTime"`
			LogIndex       int64  `json:"logIndex"`
			LogID          string `json:"logID"`
		} `json:"Payload"`
		SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
	}
	require.NoError(t, json.Unmarshal([]byte(bundleJSON), &b))
	require.EqualValues(t, 7, b.Payload.LogIndex)
	require.EqualValues(t, 12345, b.Payload.IntegratedTime)
	require.Equal(t, hex.EncodeToString(logID), b.Payload.LogID)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("body")), b.Payload.Body)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("set")), b.SignedEntryTimestamp)

	// Timestamp annotation has the right shape.
	tsJSON := ann["dev.sigstore.cosign/rfc3161timestamp"]
	require.NotEmpty(t, tsJSON)
	var ts struct {
		SignedRFC3161Timestamp string `json:"SignedRFC3161Timestamp"`
	}
	require.NoError(t, json.Unmarshal([]byte(tsJSON), &ts))
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("ts")), ts.SignedRFC3161Timestamp)
}

func TestDSSELayerForEnvelopeBundle(t *testing.T) {
	t.Parallel()
	bun := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			Content: &protobundle.Bundle_DsseEnvelope{
				DsseEnvelope: &protodsse.Envelope{
					PayloadType: "x",
					Payload:     []byte("p"),
				},
			},
			VerificationMaterial: &protobundle.VerificationMaterial{},
		},
	}
	data, material, err := dsseLayerForEnvelope(bun)
	require.NoError(t, err)
	require.NotNil(t, material)
	require.NotEmpty(t, data)
	require.True(t, strings.Contains(string(data), `"payloadType"`))
}

func TestDSSELayerForEnvelopeBundleWithoutDSSE(t *testing.T) {
	t.Parallel()
	bun := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			Content: &protobundle.Bundle_MessageSignature{
				MessageSignature: &protocommon.MessageSignature{},
			},
		},
	}
	_, _, err := dsseLayerForEnvelope(bun)
	require.Error(t, err)
}

func TestDSSELayerForEnvelopePlainDSSE(t *testing.T) {
	t.Parallel()
	env := &dsse.Envelope{
		Envelope: &protodsse.Envelope{
			PayloadType: "x",
			Payload:     []byte("p"),
		},
	}
	data, material, err := dsseLayerForEnvelope(env)
	require.NoError(t, err)
	require.Nil(t, material)
	require.True(t, strings.Contains(string(data), `"payloadType"`))
}

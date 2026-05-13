// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/google/go-containerregistry/pkg/crane"
	ggcr "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/envelope/dsse"
)

// dsseEnvelopeMediaType is the layer media type cosign uses for DSSE-wrapped
// attestation payloads in the legacy `.att` tag layout.
const dsseEnvelopeMediaType = "application/vnd.dsse.envelope.v1+json"

var _ attestation.Storer = (*Collector)(nil)

// Store implements the attestation.Storer interface. Each envelope is appended
// as a DSSE layer to the cosign-style attestation image at
// `<repo>:sha256-<digest>.att`. If an attestation image already exists at that
// tag, its existing layers are preserved (append-on-write, mirroring cosign).
//
// Bundle envelopes (`*bundle.Envelope`) are unwrapped: the DSSE payload is
// pushed as the layer body, and any sigstore verification material is hoisted
// into the cosign layer annotations (`dev.sigstore.cosign/certificate`,
// `dev.sigstore.cosign/bundle`, `dev.sigstore.cosign/rfc3161timestamp`) so the
// resulting image is fully round-trippable with cosign and with this
// collector's own `Fetch`.
func (c *Collector) Store(ctx context.Context, _ attestation.StoreOptions, envelopes []attestation.Envelope) error {
	if len(envelopes) == 0 {
		return nil
	}

	imageInfo, err := parseImageReference(ctx, c.Options.Reference, c.craneOpts()...)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
	}

	attTag := fmt.Sprintf(
		"%s/%s:%s.att",
		imageInfo.Registry, imageInfo.Repository,
		strings.Replace(imageInfo.Digest, "sha256:", "sha256-", 1),
	)

	base, err := pullExistingOrEmpty(ctx, attTag, c.craneOpts()...)
	if err != nil {
		return fmt.Errorf("preparing base attestation image: %w", err)
	}

	addendums := make([]mutate.Addendum, 0, len(envelopes))
	for i, env := range envelopes {
		layerBytes, material, err := dsseLayerForEnvelope(env)
		if err != nil {
			return fmt.Errorf("preparing layer for envelope %d: %w", i, err)
		}
		annotations, err := cosignAnnotationsFromMaterial(material)
		if err != nil {
			return fmt.Errorf("building cosign annotations for envelope %d: %w", i, err)
		}
		addendums = append(addendums, mutate.Addendum{
			Layer:       static.NewLayer(layerBytes, dsseEnvelopeMediaType),
			Annotations: annotations,
		})
	}

	img, err := mutate.Append(base, addendums...)
	if err != nil {
		return fmt.Errorf("appending attestation layers: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)

	opts := append([]crane.Option{crane.WithContext(ctx)}, c.craneOpts()...)
	if err := crane.Push(img, attTag, opts...); err != nil {
		return fmt.Errorf("pushing attestation image to %s: %w", attTag, err)
	}
	return nil
}

// pullExistingOrEmpty fetches the current attestation image at attTag so its
// layers can be preserved when new attestations are appended. A
// MANIFEST_UNKNOWN / 404 response is treated as "no attestations yet" and an
// empty image is returned instead.
func pullExistingOrEmpty(ctx context.Context, attTag string, opts ...crane.Option) (ggcr.Image, error) {
	pullOpts := append([]crane.Option{crane.WithContext(ctx)}, opts...)
	img, err := crane.Pull(attTag, pullOpts...)
	if err == nil {
		return img, nil
	}
	if isNotFound(err) {
		return empty.Image, nil
	}
	return nil, err
}

// isNotFound returns true when err signals that a registry manifest does not
// exist yet (404 / MANIFEST_UNKNOWN). Anything else is treated as a real
// failure so we don't silently drop existing attestations.
func isNotFound(err error) bool {
	var tErr *transport.Error
	if !errors.As(err, &tErr) {
		return false
	}
	if tErr.StatusCode == http.StatusNotFound {
		return true
	}
	for _, d := range tErr.Errors {
		if d.Code == transport.ManifestUnknownErrorCode || d.Code == transport.NameUnknownErrorCode {
			return true
		}
	}
	return false
}

// dsseLayerForEnvelope returns the DSSE JSON bytes that should be used as the
// `.att` layer body for env, along with any sigstore verification material
// that should be hoisted into cosign layer annotations.
//
// For `*bundle.Envelope` the embedded DSSE envelope and verification material
// are extracted directly. For `*dsse.Envelope` the wrapped protobuf DSSE is
// marshaled and no material is returned. Anything else is JSON-marshaled
// best-effort and the caller's verifier is responsible for making sense of
// the resulting layer.
func dsseLayerForEnvelope(env attestation.Envelope) ([]byte, *protobundle.VerificationMaterial, error) {
	switch e := env.(type) {
	case *bundle.Envelope:
		de := e.GetDsseEnvelope()
		if de == nil {
			return nil, nil, fmt.Errorf("bundle envelope does not contain a DSSE envelope; only DSSE-wrapped attestations can be stored as cosign .att layers")
		}
		data, err := marshalProto(de)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling DSSE envelope: %w", err)
		}
		return data, e.GetVerificationMaterial(), nil
	case *dsse.Envelope:
		if e.Envelope == nil {
			return nil, nil, fmt.Errorf("dsse envelope is empty")
		}
		data, err := marshalProto(e.Envelope)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling DSSE envelope: %w", err)
		}
		return data, nil, nil
	default:
		data, err := json.Marshal(env)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling envelope: %w", err)
		}
		return data, nil, nil
	}
}

// marshalProto serializes a google-protobuf message using protojson with the
// defaults that match what cosign / sigstore consumers expect for DSSE layer
// bodies.
func marshalProto(m proto.Message) ([]byte, error) {
	return (protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: false}).Marshal(m)
}

// cosignAnnotationsFromMaterial converts sigstore verification material into
// the cosign layer annotation set used by the legacy .att tag layout. Returns
// nil when there's nothing to hoist (e.g. plain key-signed DSSE).
func cosignAnnotationsFromMaterial(material *protobundle.VerificationMaterial) (map[string]string, error) {
	if material == nil {
		return nil, nil
	}
	annotations := map[string]string{}

	if chain := material.GetX509CertificateChain(); chain != nil {
		certs := chain.GetCertificates()
		if len(certs) > 0 && len(certs[0].GetRawBytes()) > 0 {
			pemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certs[0].GetRawBytes(),
			})
			if pemBytes == nil {
				return nil, fmt.Errorf("encoding signing certificate to PEM")
			}
			annotations["dev.sigstore.cosign/certificate"] = string(pemBytes)
		}
	}

	if entries := material.GetTlogEntries(); len(entries) > 0 {
		ann, err := buildCosignBundleAnnotation(entries[0])
		if err != nil {
			return nil, fmt.Errorf("building bundle annotation: %w", err)
		}
		annotations["dev.sigstore.cosign/bundle"] = ann
	}

	if td := material.GetTimestampVerificationData(); td != nil {
		if ts := td.GetRfc3161Timestamps(); len(ts) > 0 && len(ts[0].GetSignedTimestamp()) > 0 {
			ann, err := buildCosignTimestampAnnotation(ts[0])
			if err != nil {
				return nil, fmt.Errorf("building rfc3161 timestamp annotation: %w", err)
			}
			annotations["dev.sigstore.cosign/rfc3161timestamp"] = ann
		}
	}

	if len(annotations) == 0 {
		return nil, nil
	}
	return annotations, nil
}

// buildCosignBundleAnnotation re-serializes a rekor transparency log entry
// into the JSON shape that cosign embeds in the
// `dev.sigstore.cosign/bundle` layer annotation. It is the inverse of
// getVerificationMaterialTlogEntries in collector.go.
func buildCosignBundleAnnotation(entry *protorekor.TransparencyLogEntry) (string, error) {
	payload := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(entry.GetCanonicalizedBody()),
		"integratedTime": entry.GetIntegratedTime(),
		"logIndex":       entry.GetLogIndex(),
	}
	if logID := entry.GetLogId(); logID != nil && len(logID.GetKeyId()) > 0 {
		payload["logID"] = hex.EncodeToString(logID.GetKeyId())
	}

	wrapper := map[string]any{
		"Payload": payload,
	}
	if ip := entry.GetInclusionPromise(); ip != nil && len(ip.GetSignedEntryTimestamp()) > 0 {
		wrapper["SignedEntryTimestamp"] = base64.StdEncoding.EncodeToString(ip.GetSignedEntryTimestamp())
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(wrapper); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

// buildCosignTimestampAnnotation produces the JSON body of the
// `dev.sigstore.cosign/rfc3161timestamp` annotation from a SignedRFC3161
// timestamp.
func buildCosignTimestampAnnotation(ts *protocommon.RFC3161SignedTimestamp) (string, error) {
	payload := map[string]string{
		"SignedRFC3161Timestamp": base64.StdEncoding.EncodeToString(ts.GetSignedTimestamp()),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
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
	"io"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/hasher"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	ggcr "github.com/google/go-containerregistry/pkg/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/carabiner-dev/collector/envelope/bundle"
)

var TypeMoniker = "coci"

// ImageInfo contains parsed information about a container image reference
type ImageInfo struct {
	OriginalRef string
	Registry    string
	Repository  string
	Tag         string
	Digest      string
	Identifier  string
	IsDigest    bool
}

func parseImageReference(ctx context.Context, ref string) (*ImageInfo, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	info := &ImageInfo{
		OriginalRef: ref,
		Registry:    parsedRef.Context().RegistryStr(),
		Repository:  parsedRef.Context().RepositoryStr(),
		Identifier:  parsedRef.Identifier(),
	}

	// Check if it's a tag or digest reference
	switch v := parsedRef.(type) {
	case name.Tag:
		info.Tag = v.TagStr()
		info.IsDigest = false

		digest, err := crane.Digest(ref, crane.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("getting reference digest: %w", err)
		}
		info.Digest = digest
	case name.Digest:
		info.Digest = v.DigestStr()
		info.IsDigest = true
	}

	return info, nil
}

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithReference(istr))
}

var _ attestation.Fetcher = (*Collector)(nil)

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := defaultOptions
	for _, fn := range funcs {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Collector{
		Options: opts,
	}, nil
}

type (
	optFn   = func(*Options) error
	Options struct {
		Reference string
	}
)

func WithReference(ref string) optFn {
	return func(o *Options) error {
		_, err := name.ParseReference(ref)
		if err != nil {
			return err
		}
		o.Reference = ref // perhaps parse?
		return nil
	}
}

func (o *Options) Validate() error {
	return nil
}

var defaultOptions = Options{}

type Collector struct {
	Options Options
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	imageInfo, err := parseImageReference(ctx, c.Options.Reference)
	if err != nil {
		return nil, err
	}

	// Fetch the manifest of the attached attestations:
	manifestData, err := crane.Manifest(
		fmt.Sprintf(
			"%s/%s:%s.att",
			imageInfo.Registry, imageInfo.Repository,
			strings.Replace(imageInfo.Digest, "sha256:", "sha256-", 1),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("fetting attestations manifest: %w", err)
	}

	manifest, err := ggcr.ParseManifest(bytes.NewReader(manifestData))
	if err != nil {
		return nil, fmt.Errorf("parsing attestations manifest: %w", err)
	}
	atts := []attestation.Envelope{}

	// TODO(puerco): Paralellize these fetches
	// Cycle each layer and build a sigstore envelope from the blob data and annotations
	for i := range manifest.Layers {
		// We can only parse DSSE for now
		if manifest.Layers[i].MediaType != "application/vnd.dsse.envelope.v1+json" {
			continue
		}

		envelope, err := getAttestationBundle(ctx, imageInfo, &manifest.Layers[i])
		if err != nil {
			return nil, fmt.Errorf("generating bundle from layer %d: %w", i, err)
		}

		atts = append(atts, envelope)
	}
	return atts, nil
}

// dsseEnvelopeFromOCILayer this reads the DSSE envelope containing the attestation
func dsseEnvelopeFromOCILayer(ctx context.Context, imageInfo *ImageInfo, l *ggcr.Descriptor) (*protobundle.Bundle_DsseEnvelope, error) {
	// Build the attestation blob reference
	attRef := imageInfo.Registry + "/" + imageInfo.Repository + "@" + l.Digest.String()
	layer, err := crane.PullLayer(attRef, crane.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("pulling layer data: %w", err)
	}

	// Parse the DSSE envelop from the signed contents
	blob, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("fetching blob data: %w", err)
	}
	defer blob.Close() //nolint:errcheck

	unmarshaler := jsonpb.Unmarshaler{}

	// Unmarshal the data
	dsseEnv := &protodsse.Envelope{}
	if err := unmarshaler.Unmarshal(blob, dsseEnv); err != nil {
		return nil, fmt.Errorf("unmarshaling dsse envelope: %w", err)
	}

	// Return the wrapped envelope
	return &protobundle.Bundle_DsseEnvelope{DsseEnvelope: dsseEnv}, nil
}

// Some of these functions were adapted to verify DSSE envelopes form the handy
// image verification example in:
// https://github.com/sigstore/sigstore-go/blob/8997a46ef2bef0f88b9e3aef1c45b6dbc0096b55/examples/oci-image-verification/main.go

func verificationMaterialFromOCILayer(layer *ggcr.Descriptor) (*protobundle.VerificationMaterial, error) {
	certData, ok := layer.Annotations["dev.sigstore.cosign/certificate"]
	if !ok {
		return nil, errors.New("certificate not found in layer data")
	}

	block, _ := pem.Decode([]byte(certData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}
	// 3. Construct the X509 certificate chain
	certs := &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{&signingCert},
		},
	}

	// 2. Get the transparency log entries
	tlogEntries, err := getVerificationMaterialTlogEntries(layer)
	if err != nil {
		return nil, fmt.Errorf("error getting tlog entries: %w", err)
	}

	timestampEntries, err := getVerificationMaterialTimestampEntries(layer)
	if err != nil {
		return nil, fmt.Errorf("error getting timestamp entries: %w", err)
	}

	// 3. Construct the verification material
	return &protobundle.VerificationMaterial{
		Content:                   certs,
		TlogEntries:               tlogEntries,
		TimestampVerificationData: timestampEntries,
	}, nil
}

func getVerificationMaterialTimestampEntries(manifestLayer *ggcr.Descriptor) (*protobundle.TimestampVerificationData, error) {
	// 1. Get the bundle annotation
	ts, ok := manifestLayer.Annotations["dev.sigstore.cosign/rfc3161timestamp"]
	if !ok {
		return nil, nil
	}
	// 2. Get the key/value pairs maps
	var keyValPairs map[string]string
	err := json.Unmarshal([]byte(ts), &keyValPairs)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON blob into key/val map: %w", err)
	}
	// 3. Verify the key "SignedRFC3161Timestamp" is present
	if _, ok := keyValPairs["SignedRFC3161Timestamp"]; !ok {
		return nil, errors.New("error getting SignedRFC3161Timestamp from key/value pairs")
	}
	// 4. Decode the base64 encoded timestamp
	der, err := base64.StdEncoding.DecodeString(keyValPairs["SignedRFC3161Timestamp"])
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 encoded timestamp: %w", err)
	}
	// 4. Construct the timestamp entry list
	return &protobundle.TimestampVerificationData{
		Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
			{
				SignedTimestamp: der,
			},
		},
	}, nil
}

// getAttestationBundle reads the signes contents from a layer and returns a synthesized bundle
// to use in ouor standard verification process
func getAttestationBundle(ctx context.Context, imageInfo *ImageInfo, layer *ggcr.Descriptor) (*bundle.Envelope, error) {
	dsseEnv, err := dsseEnvelopeFromOCILayer(ctx, imageInfo, layer)
	if err != nil {
		return nil, fmt.Errorf("error getting dsse envelope from layer: %w", err)
	}

	material, err := verificationMaterialFromOCILayer(layer)
	if err != nil {
		return nil, fmt.Errorf("getting verification material: %w", err)
	}

	mt, err := sbundle.MediaTypeString("v0.3")
	if err != nil {
		return nil, err
	}

	envelope := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			MediaType:            mt,
			VerificationMaterial: material,
			Content:              dsseEnv,
		},
	}

	hset, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(dsseEnv.DsseEnvelope.GetPayload())})
	if err != nil {
		return nil, fmt.Errorf("hashing dsse envelope: %w", err)
	}

	origin := hset.ToResourceDescriptors()
	origin[0].Uri = fmt.Sprintf(
		"oci:%s/%s:%s.att", imageInfo.Registry, imageInfo.Repository,
		strings.Replace(layer.Digest.String(), "sha256:", "sha256-", 1),
	)
	envelope.GetPredicate().SetOrigin(origin[0])

	return envelope, nil
}

// getVerificationMaterialTlogEntries returns any transparency log entries found in the layer
func getVerificationMaterialTlogEntries(manifestLayer *ggcr.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	bun, ok := manifestLayer.Annotations["dev.sigstore.cosign/bundle"]
	if !ok {
		return nil, fmt.Errorf("unable to find bundle annotation in layer")
	}

	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(bun), &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}

	if _, ok := jsonData["Payload"]; !ok {
		return []*protorekor.TransparencyLogEntry{}, nil
	}
	if _, ok := jsonData["SignedEntryTimestamp"]; !ok {
		return []*protorekor.TransparencyLogEntry{}, nil
	}

	// Log index, log ID, integrated time, signed entry timestamp and body
	set, ok := jsonData["SignedEntryTimestamp"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting SignedEntryTimestamp")
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(set)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}

	logIndex, ok := jsonData["Payload"].(map[string]interface{})["logIndex"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting logIndex")
	}
	li, ok := jsonData["Payload"].(map[string]interface{})["logID"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting logID")
	}
	logID, err := hex.DecodeString(li)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	integratedTime, ok := jsonData["Payload"].(map[string]interface{})["integratedTime"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting integratedTime")
	}

	// 3. Unmarshal the body and extract the rekor KindVersion details
	body, ok := jsonData["Payload"].(map[string]interface{})["body"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting body")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding body: %w", err)
	}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}

	var apiVersion, kind string
	if v, ok := jsonData["apiVersion"].(string); ok {
		apiVersion = v
	}

	if v, ok := jsonData["kind"].(string); ok {
		kind = v
	}

	// 4. Construct the transparency log entry list
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(logIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    kind,
				Version: apiVersion,
			},
			IntegratedTime: int64(integratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			InclusionProof:    nil,
			CanonicalizedBody: bodyBytes,
		},
	}, nil
}

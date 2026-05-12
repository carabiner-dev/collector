// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/hasher"
	"github.com/carabiner-dev/signer"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/collector/envelope/bare"
	"github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/envelope/dsse"
)

type Format string

const (
	FormatDSSE     Format = "dsse"
	FormatBare     Format = "bare"
	FormatJSONL    Format = "jsonl"
	FormatBundleV3 Format = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// ParserList wraps a map listing the loaded parsers to expose convenience methods
type ParserList map[Format]attestation.EnvelopeParser

var Parsers = ParserList{
	FormatDSSE:     &dsse.Parser{},
	FormatBundleV3: &bundle.Parser{},
}

// ParseFiles takes a list of paths and parses envelopes directly from them
func (list *ParserList) ParseFiles(paths []string) ([]attestation.Envelope, error) {
	atts := []attestation.Envelope{}
	hashset, err := hasher.New().HashFiles(paths)
	if err != nil {
		return nil, fmt.Errorf("hashing attestations: %w", err)
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening file: %w", err)
		}
		defer f.Close() //nolint:errcheck
		parsed, err := list.Parse(f)
		if err != nil {
			return nil, fmt.Errorf("parsing data: %w", err)
		}

		for j := range parsed {
			hset := (*hashset)[path]
			parsed[j].GetPredicate().SetOrigin(
				hset.ToResourceDescriptor(),
			)
		}

		atts = append(atts, parsed...)
	}
	return atts, nil
}

// Parse takes a reader and parses
func (list *ParserList) Parse(r io.Reader) ([]attestation.Envelope, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading atetstation data: %w", err)
	}
	for f, parser := range *list {
		logrus.Debugf("Checking if envelope is %s", f)
		env, err := parser.ParseStream(bytes.NewReader(data))
		if err == nil {
			logrus.Debugf("Found envelope type: %s ", f)
			return env, nil
		}
		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			return nil, err
		}
	}

	// If we're here, then we treat the file as a bare attestation
	env, err := bare.New().ParseStream(bytes.NewReader(data))
	if err == nil {
		logrus.Debug("Parsing statement as bare JSON")
		return env, nil
	}

	return nil, attestation.ErrNotCorrectFormat
}

// FromSignedArtifact returns an attestation.Envelope from a SignedArtifact
// object as returned from the signer. It serializes the artifact to its
// canonical JSON form and parses it through the matching collector parser.
func FromSignedArtifact(artifact signer.SignedArtifact) (attestation.Envelope, error) {
	if artifact == nil {
		return nil, errors.New("signed artifact is nil")
	}

	var parser attestation.EnvelopeParser
	switch artifact.Kind() {
	case signer.ArtifactKindBundle:
		parser = &bundle.Parser{}
	case signer.ArtifactKindEnvelope:
		parser = &dsse.Parser{}
	default:
		return nil, fmt.Errorf("unsupported signed artifact kind %q", artifact.Kind())
	}

	var buf bytes.Buffer
	if _, err := artifact.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("serializing signed artifact: %w", err)
	}

	envs, err := parser.ParseStream(&buf)
	if err != nil {
		return nil, fmt.Errorf("parsing signed artifact as %s: %w", artifact.Kind(), err)
	}
	if len(envs) == 0 {
		return nil, fmt.Errorf("parser returned no envelopes for %s artifact", artifact.Kind())
	}
	return envs[0], nil
}

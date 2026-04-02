// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package tagattest synthesizes in-toto statements for annotated git tags.
//
// This is a temporary internal package that mirrors the TagStatement function
// being added to github.com/sigstore/gitsign/pkg/attest. Once gitsign releases
// that change, this package should be replaced by the upstream import.
package tagattest

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/github/smimesign/ietf-cms/protocol"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// TagTypeV01 is the predicate type for tag attestations.
// Matches github.com/sigstore/gitsign/pkg/predicate.TagTypeV01.
const TagTypeV01 = "https://gitsign.sigstore.dev/predicate/tag/v0.1"

// gitTag mirrors the proto-generated predicate.GitTag structure.
type gitTag struct {
	Source     *tag         `json:"source"`
	Signature  string       `json:"signature,omitempty"`
	SignerInfo []signerInfo `json:"signer_info,omitempty"`
}

type tag struct {
	Object     string  `json:"object"`
	ObjectType string  `json:"object_type"`
	Tag        string  `json:"tag"`
	Tagger     *author `json:"tagger,omitempty"`
	Message    string  `json:"message,omitempty"`
}

type author struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

type signerInfo struct {
	Attributes  string `json:"attributes"`
	Certificate string `json:"certificate"`
}

// TagStatement creates an in-toto statement for an annotated git tag.
// It returns an error for lightweight (non-annotated) tags.
//
// This function has the same signature and behavior as the TagStatement
// being added to github.com/sigstore/gitsign/pkg/attest.
func TagStatement(repo *gogit.Repository, remote, tagName string) (*intoto.Statement, error) {
	ref, err := repo.Tag(tagName)
	if err != nil {
		return nil, err
	}

	tagObj, err := repo.TagObject(ref.Hash())
	if err != nil {
		return nil, fmt.Errorf("tag %q is not an annotated tag", tagName)
	}

	pred := &gitTag{
		Source: &tag{
			Object:     tagObj.Target.String(),
			ObjectType: tagObj.TargetType.String(),
			Tag:        tagObj.Name,
			Tagger: &author{
				Name:  tagObj.Tagger.Name,
				Email: tagObj.Tagger.Email,
				Date:  tagObj.Tagger.When.UTC().Format(time.RFC3339),
			},
			Message: tagObj.Message,
		},
		Signature: tagObj.PGPSignature,
	}

	if pemBlock, _ := pem.Decode([]byte(tagObj.PGPSignature)); pemBlock != nil {
		sigs, err := parseSignature(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		pred.SignerInfo = sigs
	}

	// Resolve remote name for the subject.
	resolvedRemote, err := repo.Remote(remote)
	if err != nil && !errors.Is(err, gogit.ErrRemoteNotFound) {
		return nil, err
	}
	remoteName := ""
	if resolvedRemote != nil && resolvedRemote.Config() != nil && len(resolvedRemote.Config().URLs) > 0 {
		remoteName = resolvedRemote.Config().URLs[0]
	}

	// Marshal the predicate to structpb.Struct via JSON to match the
	// upstream proto-based approach.
	jsonBytes, err := json.Marshal(pred)
	if err != nil {
		return nil, err
	}
	predicateStruct := &structpb.Struct{}
	if err := protojson.Unmarshal(jsonBytes, predicateStruct); err != nil {
		return nil, err
	}

	return &intoto.Statement{
		Type: intoto.StatementTypeUri,
		Subject: []*intoto.ResourceDescriptor{
			{
				Digest: map[string]string{
					"sha1":   ref.Hash().String(),
					"gitTag": ref.Hash().String(),
				},
				Name: remoteName,
			},
		},
		Predicate:     predicateStruct,
		PredicateType: TagTypeV01,
	}, nil
}

// parseSignature extracts signer info from a CMS/PKCS7 signature.
// Mirrors the parseSignature function in gitsign/pkg/attest.
func parseSignature(raw []byte) ([]signerInfo, error) {
	ci, err := protocol.ParseContentInfo(raw)
	if err != nil {
		return nil, err
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, err
	}

	certs, err := sd.X509Certificates()
	if err != nil {
		return nil, err
	}

	out := make([]signerInfo, 0, len(sd.SignerInfos))
	for i := range sd.SignerInfos {
		cert, err := sd.SignerInfos[i].FindCertificate(certs)
		if err != nil {
			continue
		}
		b, err := cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return nil, err
		}
		sa, err := sd.SignerInfos[i].SignedAttrs.MarshaledForVerification()
		if err != nil {
			return nil, err
		}
		out = append(out, signerInfo{
			Certificate: string(b),
			Attributes:  base64.StdEncoding.EncodeToString(sa),
		})
	}

	return out, nil
}

// ResolveTagHash resolves a tag name to the hash of the tag object (for
// annotated tags) or the commit hash (for lightweight tags). This is a
// helper for callers that need the tag object hash.
func ResolveTagHash(repo *gogit.Repository, tagName string) (plumbing.Hash, error) {
	ref, err := repo.Tag(tagName)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("looking up tag %q: %w", tagName, err)
	}
	return ref.Hash(), nil
}

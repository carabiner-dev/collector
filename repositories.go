// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/carabiner-dev/attestation"

	"github.com/carabiner-dev/collector/repository/coci"
	"github.com/carabiner-dev/collector/repository/filesystem"
	"github.com/carabiner-dev/collector/repository/github"
	"github.com/carabiner-dev/collector/repository/http"
	"github.com/carabiner-dev/collector/repository/jsonl"
	"github.com/carabiner-dev/collector/repository/note"
	"github.com/carabiner-dev/collector/repository/ossrebuild"
	"github.com/carabiner-dev/collector/repository/release"
)

var (
	repositoryTypes          = map[string]RepositoryFactory{}
	ErrTypeAlreadyRegistered = errors.New("collector type already registered")
)

type RepositoryFactory func(string) (attestation.Repository, error)

var mtx sync.Mutex

func RepositoryFromString(init string) (attestation.Repository, error) {
	t, init, _ := strings.Cut(init, ":")
	if b, ok := repositoryTypes[t]; ok {
		return b(init)
	}
	return nil, fmt.Errorf("repository type unknown: %q", t)
}

// RegisterCollectorType registers a new type of collector
func RegisterCollectorType(moniker string, factory RepositoryFactory) error {
	if _, ok := repositoryTypes[moniker]; ok {
		return ErrTypeAlreadyRegistered
	}
	mtx.Lock()
	repositoryTypes[moniker] = factory
	mtx.Unlock()
	return nil
}

// RegisterCollectorType registers a new type of collector
func UnregisterCollectorType(moniker string) {
	mtx.Lock()
	delete(repositoryTypes, moniker)
	mtx.Unlock()
}

// LoadDefaultRepositoryTypes loads the default repository types into the
// in-memory list to get them ready for instantiation.
func LoadDefaultRepositoryTypes() error {
	errs := []error{}
	for t, factory := range map[string]RepositoryFactory{
		coci.TypeMoniker:       coci.Build,
		filesystem.TypeMoniker: filesystem.Build,
		github.TypeMoniker:     github.Build,
		http.TypeMoniker:       http.BuildHTTP,
		http.TypeMonikerHTTPS:  http.BuildHTTPs,
		jsonl.TypeMoniker:      jsonl.Build,
		note.TypeMoniker:       note.Build,
		ossrebuild.TypeMoniker: ossrebuild.Build,
		release.TypeMoniker:    release.Build,
	} {
		if err := RegisterCollectorType(t, factory); err != nil {
			if !errors.Is(err, ErrTypeAlreadyRegistered) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

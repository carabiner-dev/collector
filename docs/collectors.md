# Repository Collectors

The collector agent fetches attestations from a variety of sources through
repository collector drivers. Each driver implements one or more of the
`attestation.Fetcher`, `attestation.FetcherBySubject`, and
`attestation.FetcherByPredicateType` interfaces.

## filesystem (`fs`)

Walks a local or embedded `fs.FS` filesystem and parses any files with
recognized extensions (`.json`, `.jsonl`, `.spdx`, `.cdx`, `.bundle`).
JSONL files are parsed as multi-attestation bundles; all other files are
passed to the standard envelope parsers.

## git

Clones a remote git repository (shallow, single-branch, depth 1) into
memory and delegates to the **filesystem** collector to read attestations
from the cloned worktree.

## github

Fetches attestations from the GitHub Attestations API. Only supports
fetching by subject (digest). Attestations are returned as Sigstore
bundles. Also supports storing attestations via the upload endpoint.

## http / https

A general-purpose HTTP collector that fetches attestation data from one or
more URLs. Supports Go `text/template` URL patterns for subject name,
subject digest, subject URI, and predicate type, enabling the collector to
construct URLs dynamically. Responses are parsed as JSONL by default.

Depending on the configured URL templates, `New()` returns one of several
collector variants that implement different combinations of the fetcher
interfaces.

## jsonl

Reads attestations from local JSON Lines (`.jsonl`) files. Each line in the
file is an independent attestation envelope. Supports parallel parsing of
multiple files.

## note

Reads attestations stored in git commit notes. Clones the remote notes ref
and extracts JSONL-formatted attestation bundles from the note associated
with a specific commit SHA. Also supports storing attestations by pushing
notes back to the remote.

## coci (Container OCI)

Fetches attestations attached to OCI container images. Reads the `.att`
tag manifest for a given image digest, iterates the DSSE envelope layers,
and synthesizes Sigstore bundles from the layer data and annotations
(certificates, transparency log entries, RFC 3161 timestamps).

## release

Reads attestations from GitHub release assets. Constructs a virtual
filesystem from the release's downloadable assets and delegates to the
**filesystem** collector to parse them.

## ossrebuild

Fetches rebuild attestations from the Google OSS Rebuild project. Converts
package URLs (purls) in the subject URI into storage URLs and delegates to
the **http** collector to fetch the JSONL data.

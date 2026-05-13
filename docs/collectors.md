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

## dnote (Dynamic Git Notes)

A dynamic variant of the **note** collector. Instead of being preconfigured to
read from a specific commit, the dynamic notes collector creates a fixed notes
collector on the fly for each subject it encounters. When `FetchBySubject` is
called, it inspects the subjects for SHA-1 or `gitCommit` digests and
automatically constructs a notes collector targeting each commit. This makes it
suitable for scenarios where the set of commits is not known in advance.

Also supports storing attestations. When `Store` is called, the collector
inspects all envelope subjects looking for SHA-1 or `gitCommit` digests, groups
the envelopes by commit, and creates a notes collector per commit to write
them. All envelopes are validated before any writes occur — if any envelope
lacks a SHA-1 or `gitCommit` subject, an error is returned.

## coci (Container OCI)

Reads and writes attestations attached to OCI container images using the
legacy cosign tag convention (`<repo>:sha256-<digest>.att`). On read, the
`.att` manifest is fetched, each DSSE envelope layer is pulled, and a
Sigstore bundle is synthesized from the layer body plus its cosign
annotations (certificates, transparency log entries, RFC 3161 timestamps).

When `Store` is called the inverse path runs:

1. The reference is resolved to its image digest so the `.att` tag can be
   computed.
2. The existing `.att` manifest (if any) is pulled so its layers are
   preserved; new attestations are appended (cosign-style append-on-write).
   A missing tag is treated as "no attestations yet" and a fresh empty
   image is used as the base.
3. Each envelope is converted to a DSSE layer with media type
   `application/vnd.dsse.envelope.v1+json`. `*bundle.Envelope` inputs are
   unwrapped: the DSSE payload becomes the layer body and any sigstore
   verification material is hoisted back into cosign layer annotations
   (`dev.sigstore.cosign/certificate`, `dev.sigstore.cosign/bundle`,
   `dev.sigstore.cosign/rfc3161timestamp`) so the result round-trips with
   both this collector's `Fetch` and with cosign itself.
4. The resulting OCI image manifest is pushed at the `.att` tag.

Authentication uses the standard Docker keychain
(`~/.docker/config.json`, `$DOCKER_CONFIG`, configured credential helpers).
Tests and other callers can override registry options via `WithCraneOpts`
(e.g. `crane.Insecure` for an HTTP test registry). The implementation is
built directly on
[`go-containerregistry`](https://github.com/google/go-containerregistry);
it does not depend on `cosign`.

## oci (OCI Referrers)

Reads and writes Sigstore bundle attestations attached as OCI referrers.
Cosign v3 attaches signatures and attestations as OCI artifacts that
reference the subject image via the OCI Referrers API, rather than using
the `.att`/`.sig` tag convention used by the **coci** collector.

The collector queries the Referrers API for artifacts with artifact type
`application/vnd.dev.sigstore.bundle.v0.3+json`, pulls their blob layers,
and parses each as a Sigstore bundle using the standard `bundle.Parser`.

Init string format: `oci:<image-ref>` (e.g. `oci:ghcr.io/foo/bar:v1` or
`oci:ghcr.io/foo/bar@sha256:abc...`). Tag references are automatically
resolved to digests before querying referrers.

Authentication uses the Docker credential chain (`~/.docker/config.json`,
`$DOCKER_CONFIG`, `$DOCKER_AUTH_CONFIG`, and configured credential helpers)
and Docker CA certificates (`/etc/docker/certs.d`). Callers can override
this with `WithRegClientOpts` to inject custom registry hosts or transport
options.

When `Store` is called, each envelope is JSON-marshaled (the envelope is
expected to be a Sigstore bundle, e.g. `*bundle.Envelope`) and uploaded as
a new referrer pointing at the subject image:

1. The subject reference is resolved via `ManifestHead` to capture its
   digest, size, and media type.
2. The bundle bytes are pushed as a blob with media type
   `application/vnd.dev.sigstore.bundle.v0.3+json`.
3. An empty `{}` config blob with media type
   `application/vnd.oci.empty.v1+json` is pushed.
4. An OCI image manifest is built with `artifactType` set to the Sigstore
   bundle media type, the bundle blob as its single layer, and `subject`
   pointing at the resolved image digest. The manifest is pushed at its
   own content-addressable digest so the registry exposes it through the
   Referrers API.

The implementation is built directly on
[`regclient`](https://github.com/regclient/regclient); it does not depend
on `cosign`.

## release

Reads attestations from GitHub release assets. Constructs a virtual
filesystem from the release's downloadable assets and delegates to the
**filesystem** collector to parse them.

## ossrebuild

Fetches rebuild attestations from the Google OSS Rebuild project. Converts
package URLs (purls) in the subject URI into storage URLs and delegates to
the **http** collector to fetch the JSONL data.

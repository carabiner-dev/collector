# Virtual Attestations from Detached Signatures

Collectors that walk a filesystem — **filesystem** (`fs`), **release**, and
**git** — can synthesize virtual attestations when they find detached signature
files next to their companion artifacts. This turns any signed release artifact
into a queryable in-toto attestation without requiring the signer to produce one
explicitly.

## How it works

During the filesystem walk, files with recognized signature extensions are
set aside. After all regular attestation files have been parsed, the collector
runs a second pass looking for signature/artifact pairs based on filename
matching:

```
myapp-v1.2.tar.gz                  ← artifact
myapp-v1.2.tar.gz.sig              ← detached raw signature
myapp-v1.2.tar.gz.sigstore.json    ← or a sigstore bundle
```

For each pair, the collector:

1. Reads and verifies the signature.
2. Computes (or extracts) the artifact digest.
3. Builds a virtual in-toto attestation with the artifact as the subject.

The resulting envelope is returned alongside any other attestations found in
the same directory. From the caller's perspective these virtual attestations
are indistinguishable from regular ones — they can be filtered by subject,
predicate type, or any other query.

## Supported signature types

### Raw signatures (`.sig`, `.gpg`, `.asc`)

Raw detached signatures are verified using the public keys registered on the
collector agent. Keys can be provided at agent construction time or added later:

```go
agent, err := collector.New(
    collector.WithKeyFiles("release-key.pub"),
    collector.WithRepository(repo),
)
```

Or added to an existing agent:

```go
agent.AddKeys(myKeyProvider)
```

When the agent distributes keys to repositories it uses the
`repository.SignatureVerifier` interface. Any collector implementing `SetKeys`
will receive them automatically.

For a raw signature pair to produce a virtual attestation:

- The companion artifact **must** exist in the same directory.
- At least one of the configured keys must successfully verify the signature.

The artifact is read and hashed to form the attestation subject.

### Sigstore message-signature bundles (`.sigstore.json`)

Sigstore bundles that contain a `messageSignature` (as opposed to a DSSE
envelope) are verified against the Sigstore trust root. The signing identity is
extracted from the bundle's certificate.

Key advantages of sigstore bundles:

- **No keys needed** — verification uses the public Sigstore infrastructure.
- **No artifact read required** — the artifact digest is embedded in the
  bundle's `messageSignature.messageDigest`, so the collector does not need to
  read or hash the companion file.

If the `.sigstore.json` file contains a DSSE envelope bundle (i.e. it wraps a
full attestation rather than a bare message signature), it is parsed as a
regular attestation instead.

## Virtual attestation format

Virtual attestations use the predicate type:

```
https://carabiner.dev/ampel/signature/v1
```

The envelope's statement has:

- **Subject**: a single `ResourceDescriptor` with the artifact filename and its
  digest (computed for raw signatures, extracted from the bundle for sigstore).
- **Predicate**: an empty JSON object (`{}`).
- **Verification**: contains the verified signing identity — either a key ID
  (for raw signatures) or a Sigstore identity with issuer and SAN (for sigstore
  bundles).

## Configuring extensions

The filesystem collector recognizes these extensions by default:

| Type | Default extensions |
| --- | --- |
| Raw signatures | `.sig`, `.gpg`, `.asc` |
| Sigstore bundles | `.sigstore.json` |

Both can be overridden when constructing the filesystem collector directly:

```go
fscollector, err := filesystem.New(
    filesystem.WithFS(myFS),
    filesystem.WithSignatureExtensions([]string{".sig", ".asc"}),
    filesystem.WithSigstoreBundleExtensions([]string{".sigstore.json", ".bundle.json"}),
)
```

## Which collectors support this

| Collector | Virtual attestation support | Notes |
| --- | --- | --- |
| **filesystem** (`fs`) | Yes | Core implementation lives here |
| **release** | Yes | Delegates to filesystem; keys propagated via `SetKeys` |
| **git** | Yes | Delegates to filesystem |
| **All others** | No | Not filesystem-based |

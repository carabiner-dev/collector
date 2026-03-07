# Read and Attestation Limits

The collector agent enforces two kinds of limits to prevent resource
exhaustion when reading from external sources:

1. **MaxReadSize** — caps the number of bytes read from any single source.
2. **Limit** — caps the number of attestation envelopes returned.

Both values are set on the agent and propagated to every repository
collector through `attestation.FetchOptions`.

## MaxReadSize

Controls the maximum number of bytes the collector will read from a single
external source (an HTTP response body, a file, an OCI blob, etc.).

| Level | Field | Default |
|-------|-------|---------|
| Agent options | `Options.MaxReadSize` | `DefaultMaxReadSize` (7 MiB) |
| Per-fetch | `FetchOptions.MaxReadSize` | Inherited from agent |
| Collector fallback | `readlimit.DefaultMaxReadSize` | 7 MiB |

When the agent calls a repository's `Fetch*` method it copies its
configured `MaxReadSize` into the `FetchOptions` that are passed down. If
`MaxReadSize` is 0 when it reaches a collector, the collector falls back to
`readlimit.DefaultMaxReadSize` (7 MiB).

### Configuring MaxReadSize

```go
// At agent creation (sets the default for all fetches):
agent, _ := collector.New(
    collector.WithMaxReadSize(10 << 20), // 10 MiB
)

// Per-fetch override via FetchOptionsFunc is also possible.
```

### How MaxReadSize is enforced per collector

| Collector | Enforcement |
|-----------|-------------|
| **github** | HTTP response body wrapped with `io.LimitReader` before JSON decoding |
| **http** | Response byte-slice length checked against the limit after download |
| **coci** | OCI layer blob wrapped with `io.LimitReader` before protobuf unmarshal |
| **jsonl** | File reader wrapped with `io.LimitReader` before JSONL iteration |
| **note** | Git notes reader wrapped with `io.LimitReader` before JSONL iteration |
| **filesystem** | File size checked via `DirEntry.Info()` before reading |
| **git** | Delegates to **filesystem** (limit enforced there) |
| **release** | Delegates to **filesystem** (limit enforced there) |
| **ossrebuild** | Delegates to **http** (limit enforced there) |

## Limit (maximum attestations)

Controls the maximum number of attestation envelopes a collector will
return from a single `Fetch*` call.

| Level | Field | Default |
|-------|-------|---------|
| Per-fetch | `FetchOptions.Limit` | 0 (no limit) |

A value of 0 means no limit is applied.

### Configuring Limit

```go
// Per-fetch:
atts, _ := agent.Fetch(ctx, collector.WithLimit(100))
```

### How Limit is enforced per collector

The collectors try to stop work as early as possible once the limit is
reached, avoiding unnecessary network requests, file reads, or parsing:

| Collector | Strategy |
|-----------|----------|
| **github** | Stops iterating over subject digests once the limit is reached, avoiding further API calls |
| **http** | Stops accumulating results from URL responses and returns early |
| **coci** | Breaks the OCI manifest layer loop, skipping remaining layer pulls |
| **jsonl** | Breaks the JSONL line iteration loop, stopping parsing early |
| **note** | Breaks the JSONL line iteration loop, stopping parsing early |
| **filesystem** | Exits `fs.WalkDir` early via a sentinel error, stopping file reads |
| **git** | Delegates to **filesystem** (limit enforced there) |
| **release** | Delegates to **filesystem** (limit enforced there) |
| **ossrebuild** | Delegates to **http** (limit enforced there) |

Note: the agent itself also applies `FetchOptions.Limit` after merging
results from all repositories, so even if an individual collector returns
slightly more results than expected the final output is always trimmed.

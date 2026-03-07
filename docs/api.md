# Writing a Repository Collector

This document explains how to write your own repository collector, either
as an external package in your application or as a contribution to this
repository.

## Interfaces

The collector agent interacts with repositories through a small family of
interfaces defined in the
[`github.com/carabiner-dev/attestation`](https://github.com/carabiner-dev/attestation)
package. A repository expresses its capabilities by implementing one or
more of them.

### Repository

```go
type Repository interface{}
```

`Repository` is a marker interface. All collectors must satisfy it, but it
has no methods of its own. Capabilities are expressed by additionally
implementing the fetcher and/or storer interfaces below.

### Fetcher interfaces

All fetcher methods receive a `context.Context` and a `FetchOptions`
struct. Collectors are expected to honor the options (see
[limits.md](limits.md) for details on `MaxReadSize` and `Limit`).

```go
type Fetcher interface {
    Fetch(context.Context, FetchOptions) ([]Envelope, error)
}
```

`Fetcher` is the base interface. Every collector that can retrieve
attestations must implement it. `Fetch` returns attestations in whatever
order the backend provides, without any filtering.

```go
type FetcherBySubject interface {
    FetchBySubject(context.Context, FetchOptions, []Subject) ([]Envelope, error)
}
```

Implement `FetcherBySubject` when your backend can natively filter by
subject hashes. The agent will call `FetchBySubject` instead of `Fetch`
when it has subjects to match, avoiding a full scan and post-filter.

```go
type FetcherByPredicateType interface {
    FetchByPredicateType(context.Context, FetchOptions, []PredicateType) ([]Envelope, error)
}
```

Implement `FetcherByPredicateType` when your backend can natively filter by
predicate type.

```go
type FetcherByPredicateTypeAndSubject interface {
    FetchByPredicateTypeAndSubject(context.Context, FetchOptions, []PredicateType, []Subject) ([]Envelope, error)
}
```

Implement `FetcherByPredicateTypeAndSubject` when your backend can filter
by both predicate type and subject in a single query.

If a collector does not implement one of the specialized interfaces, the
agent falls back to calling `Fetch` and filtering the results in memory.
You only need to implement the interfaces that your backend can take
advantage of.

If a method is not supported at all, return `attestation.ErrFetcherMethodNotImplemented`.

### Storer interface

```go
type Storer interface {
    Store(context.Context, StoreOptions, []Envelope) error
}
```

Implement `Storer` if your backend can persist attestations. The agent
calls `Store` for every configured storer repository when the user invokes
`agent.Store()`.

### FetchOptions

```go
type FetchOptions struct {
    Limit       int
    MaxReadSize int64
    Query       *Query
}
```

Collectors should honor the following fields:

- **`Limit`**: maximum number of attestation envelopes to return. A value
  of 0 means no limit.
- **`MaxReadSize`**: maximum bytes to read from any single external source.
  A value of 0 means fall back to the default (7 MiB). See
  [limits.md](limits.md).
- **`Query`**: an optional query with filters to apply after fetching.

## Using a collector externally

You can write a collector in your own package and register it with the
agent at runtime without modifying this repository.

### Option A: add it directly to the agent

```go
myRepo, _ := mypackage.NewCollector(/* ... */)

agent, _ := collector.New(
    collector.WithRepository(myRepo),
)
```

The agent accepts any value that satisfies `attestation.Repository` (which
all fetcher/storer implementations do implicitly). This is the simplest
approach when your application creates the agent and the repository
programmatically.

### Option B: register a factory for string-based initialization

If your application uses string-based repository initialization (e.g. from
configuration files), you can register a factory function:

```go
collector.RegisterCollectorType("mytype", func(init string) (attestation.Repository, error) {
    return mypackage.NewCollector(mypackage.WithConfig(init))
})
```

After registration, repositories of your type can be created with:

```go
agent.AddRepositoryFromString("mytype:some-config-value")
```

## Contributing a collector to this repository

If your collector is generally useful, consider contributing it. The
built-in collectors follow a consistent structure:

### Package layout

Create a new package under `repository/`:

```
repository/mytype/
    collector.go    # Collector struct, New(), Fetch*/Store methods
    options.go      # Options struct, functional option helpers, defaults
    collector_test.go
    testdata/       # Test fixtures
```

### Conventions

1. **Export a `TypeMoniker` variable** with a short, lowercase identifier
   for your collector type (e.g. `"mytype"`).

2. **Export a `Build` variable** with a `RepositoryFactory` signature so
   the collector can be instantiated from a string:

   ```go
   var Build = func(init string) (attestation.Repository, error) {
       return New(WithConfig(init))
   }
   ```

3. **Use functional options** for configuration (`New(opts ...optFn)`).

4. **Honor `FetchOptions.MaxReadSize`** by wrapping external readers with
   `readlimit.Reader()` from `internal/readlimit`, or checking sizes
   before reading data into memory.

5. **Honor `FetchOptions.Limit`** by stopping iteration early when the
   limit is reached.

6. **Add a compile-time interface check**:

   ```go
   var _ attestation.Fetcher = (*Collector)(nil)
   ```

7. **Register your collector** by adding it to the factory map in
   `repositories.go` inside `LoadDefaultRepositoryTypes()`.

### Skeleton

```go
package mytype

import (
    "context"

    "github.com/carabiner-dev/attestation"

    "github.com/carabiner-dev/collector/internal/readlimit"
)

var TypeMoniker = "mytype"

var Build = func(init string) (attestation.Repository, error) {
    return New(WithConfig(init))
}

var _ attestation.Fetcher = (*Collector)(nil)

type Collector struct {
    Options Options
}

type Options struct {
    Config string
}

type optFn func(*Options)

func WithConfig(cfg string) optFn {
    return func(o *Options) { o.Config = cfg }
}

func New(fns ...optFn) (*Collector, error) {
    opts := Options{}
    for _, fn := range fns {
        fn(&opts)
    }
    return &Collector{Options: opts}, nil
}

func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
    _ = readlimit.Resolve(opts.MaxReadSize) // use when reading data

    var ret []attestation.Envelope
    // ... fetch attestations from your backend ...

    // Honor the limit
    if opts.Limit > 0 && len(ret) > opts.Limit {
        ret = ret[:opts.Limit]
    }
    return ret, nil
}
```

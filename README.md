# Carabiner Attestation Collector and Parsers

This repository contains the carabiner attestation collector and various
parsers for envelopes, statment types (well only in-toto is upported ATM!)
and predicates.

The two main consumers of this repository are 
[🔴🟡🟢 AMPEL](https://github.com/carabiner-dev/ampel)
and [🥨 bnd](https://github.com/carabiner-dev/bnd) but any project that
needs to download, read and sotr attestations can benefit from this module.

This project handles attestations using an abstractionabove the vanilla intoto
attestations by relying on the
[Carabiner Attestation Framework](https://github.com/carabiner-dev/attestation).

## Copyright

This project is Copyright &copy; by Carabiner Systems and released under the Apache-2.0 license, meaning you can use it and contribute back ideas and patches.
If you use the collector, be sure to let us know!!
 
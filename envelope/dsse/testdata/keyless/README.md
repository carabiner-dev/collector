# Keyless DSSE fixtures

`generator.intoto.jsonl` is a real provenance envelope from the
original slsa-verifier's test data (Apache-2.0,
https://github.com/slsa-framework/slsa-verifier): a DSSE envelope
signed keyless by the slsa-github-generator, carrying its Fulcio
certificate in the non-standard `cert` signature field. `rekor-response.json` is the Rekor SearchLogQuery response
for it, frozen from rekor.sigstore.dev so the tests verify the
real log entry offline.

# PAJIN Web analysis authorization offline issuer

This package is a physically separate provisioning and issuance utility for the
WEB-007 one-call authorization boundary. It is intentionally outside PAJIN's
main `src`, `scripts`, container, and runtime paths. The distribution has no
dependency on or import from the `pajin` package; it implements only the exact
public trust-anchor and V2 request, statement, and bundle wire contracts needed
to sign one request. PAJIN parses and verifies the emitted public artifacts
independently.

The utility has two commands:

- `provision` creates one random Ed25519 raw private seed, its public trust
  anchor, and the trust-anchor digest in distinct files.
- `issue` reads that key and a canonical authorization-request artifact and
  creates exactly one short-lived signed authorization bundle.

Every input and output file must be owner-owned, single-link, and mode `0600`.
Its immediate parent directory must be owner-owned and mode `0700`. Path
components and file leaves are opened without following symbolic links.
Outputs are exclusive-create and are never replaced.

Private-key material is accepted only from the named local file. It is never
accepted as an argument value, environment variable, or standard input. The
execution package consumes only the public trust anchor, its independently
retained digest, and a signed bundle; it must not import this package.

The request and JSON outputs use canonical compact JSON followed by exactly one
line-feed byte. Digest files contain exactly one lowercase SHA-256 digest and a
line feed.

Example (paths shown are illustrative):

```text
pajin-web-analysis-authorization-offline provision \
  --private-key-file authority/private.seed \
  --trust-anchor-file authority/trust-anchor.json \
  --trust-anchor-digest-file authority/trust-anchor.sha256 \
  --trust-domain pajin.web-analysis.live \
  --issuer external-authorizer.invalid \
  --key-id external-key-v1 \
  --not-before 2026-09-23T00:00:00Z \
  --not-after 2026-09-24T00:00:00Z

pajin-web-analysis-authorization-offline issue \
  --private-key-file authority/private.seed \
  --trust-anchor-file authority/trust-anchor.json \
  --trust-anchor-digest-file retained/trust-anchor.sha256 \
  --authorization-request-file requests/request.json \
  --signed-bundle-file issued/authorization.json \
  --lifetime-seconds 180
```

Provisioning or issuance is not a model dispatch and grants no target, Tool,
Finding, Graph, report, retry, or general execution authority.

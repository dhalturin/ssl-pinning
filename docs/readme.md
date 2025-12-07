# Dynamic SSL-pinning

`ssl-pinning` utility is a dynamic SSL pinning service that continuously tracks the public keys of target HTTPS endpoints, maintains an up-to-date list of key fingerprints, and exposes them as signed JSON for client devices.

This allows clients to enforce SSL pinning even when certificates are rotated automatically, while preventing attackers from injecting forged fingerprints.

## Overview

Traditional SSL pinning relies on static certificate fingerprints embedded into clients. As certificates are rotated (e.g. via Let's Encrypt or automated provisioning), these pins become stale and must be updated and redeployed, which is operationally expensive and error-prone.

`ssl-pinning` utility solves this by implementing **dynamic SSL pinning**:

- it periodically connects to configured HTTPS endpoints
- extracts the public key
- computes fingerprints
- stores them in a configurable storage backend, and
- exposes the current set of fingerprints via a JSON endpoints

To prevent tampering, the JSON payload is **cryptographically signed**.
Client devices verify the signature before trusting the fingerprint list.  

Even if an attacker manages to issue a "valid" certificate for a target domain (e.g. due to CA bugs or mis-issuance), they still cannot forge a valid signed fingerprint list and transparently intercept traffic.

## Storage backends

`ssl-pinning` utility supports multiple storage backends for fingerprint state:

- `memory` - in-memory only (best for local development and tests)
- `fs` - filesystem storage on local disk
- `redis` - shared in-memory store for multiple replicas
- `postgres` - durable relational storage for high-availability setups

The backend is controlled via configuration options:

- `storage.type` (`memory`, `fs`, `redis`, `postgres`)
- `storage.dsn` (connection string for `redis`/`postgres`)
- connection-pool and dump settings (`storage.*` options described below).

The full description of the utility configuration is available [here](configuration.md).

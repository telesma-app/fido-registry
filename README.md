# telesma-app/fido-registry

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/fido-registry.svg)](https://pkg.go.dev/github.com/telesma-app/fido-registry)
[![Go](https://github.com/telesma-app/fido-registry/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/fido-registry/actions/workflows/go.yml)

`telesma-app/fido-registry` provides dependency-free Go types for the complete
numeric values, case-sensitive names, bit masks, COSE authentication profiles,
and Metadata Statement combination rules in the authenticator-characteristics
sections of FIDO Registry of Predefined Values 2.3.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Features

The root `registry` package represents every value in sections 3.1 through 3.7
of the
[FIDO Registry of Predefined Values 2.3](https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps-20260105.html#authenticator-characteristics).
`registry.Version` identifies that source version. Updating the represented
registry requires a module release; the package does not fetch registry data at
runtime.

## Installation

```sh
go get github.com/telesma-app/fido-registry@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

```go
package main

import (
	"fmt"
	"log"

	registry "github.com/telesma-app/fido-registry"
)

func main() {
	algorithm, ok := registry.ParseAuthenticationAlgorithm("secp256r1_ecdsa_sha256_raw")
	if !ok {
		log.Fatal("unregistered authentication algorithm")
	}

	name, _ := algorithm.Name()
	profile, ok := algorithm.COSEProfile()
	if !ok {
		log.Fatal("authentication algorithm has no COSE key profile")
	}

	fmt.Printf("algorithm=%#x name=%s COSE=%+v\n", algorithm, name, profile)
}
```

## Registry values and metadata

Numeric registry types expose `Parse…`, `Name`, and `Registered` for exact
bidirectional mapping. Plural bit-mask parsers reject unknown names and
duplicates but deliberately do not apply Metadata Statement policy. For bit
masks, `Registered` and `Names` accept every combination of known bits,
including zero; `ValidMetadata` applies the relevant nonempty, `MUST`, and
exclusivity rules. Registry `SHOULD` pairings remain policy decisions for
callers.

Authentication algorithms with a Registry-defined COSE key representation
also expose `COSEProfile`. Reverse lookup uses the complete `(alg, kty, crv)`
tuple, so the shared EdDSA algorithm identifier `-8` resolves Ed25519 and Ed448
without ambiguity. A COSE profile can correspond to both raw and DER Registry
signature encodings; `AuthenticationAlgorithms` returns every such value.

## Development

```sh
go test ./...
go vet ./...
```

## License

[Apache License 2.0](LICENSE).

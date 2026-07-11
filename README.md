# PANDA Go SDK

**PANDA (Private And Secure Data Access)** — AES-256-GCM field-level encryption SDK for Go services.

## Requirements

- Go ≥ 1.20

## Installation

```bash
go get github.com/jatimprovcsirt/panda-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/jatimprovcsirt/panda-go/crypto"
)

func main() {
    // 1. Set up key provider (reads PANDA_KEY_<KID> from env)
    keyProvider := crypto.NewLocalKeyProvider()

    // 2. Create cipher
    cipher := crypto.NewFieldCipher(keyProvider, nil, nil)

    // 3. Encrypt
    env, err := cipher.Encrypt([]byte("3201012501990001"), "opd-dukcapil-key-1")
    if err != nil { panic(err) }

    json, _ := env.ToJSON() // Store in TEXT column
    fmt.Println(json)

    // 4. Decrypt (masked by default)
    masked, err := cipher.Decrypt(env)
    fmt.Println(string(masked)) // "32************01"

    // 5. Decrypt (full value — audited)
    raw, err := cipher.DecryptRaw(env)
    fmt.Println(string(raw)) // "3201012501990001"
}
```

## CLI Commands

```bash
panda init --kid <key-id> --token <token>
panda rotate-key --new-kid <kid>
panda shred <kid>
panda migrate <table> <col> <kid>
panda migrate --dry-run <table> <col> <kid>
```

Build the CLI:

```bash
go build -o panda ./cmd/panda
```

## Security

See [SECURITY.md](docs/security/SECURITY.md) for responsible disclosure.

## License

MIT

module github.com/jatimprovcsirt/panda-go

go 1.24.0

require (
	github.com/go-sql-driver/mysql v1.10.0
	github.com/lib/pq v1.12.3
	github.com/spf13/cobra v1.10.2
)

//go:ignore Infisical SDK - will be used in Phase 1 for InfisicalKeyProvider
// To add: require github.com/infisical/go-sdk v0.3.0
// Currently implemented with native HTTP to minimize dependencies

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

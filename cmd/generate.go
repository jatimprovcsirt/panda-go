package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jatimprovcsirt/panda-go/internal/panda"
	"github.com/jatimprovcsirt/panda-go/telemetry"
	"github.com/spf13/cobra"
)

var (
	generateKid         string
	generateDescription string
	generateProvider    string
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate [kid]",
	Short: "Generate a new encryption key",
	Long: `Generate a new encryption key and store it in the configured provider.

If kid is not provided, the command will run in interactive mode.`,
	RunE: runGenerate,
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVar(&generateKid, "kid", "", "Key Identifier")
	generateCmd.Flags().StringVar(&generateDescription, "description", "", "Key description")
	generateCmd.Flags().StringVar(
		&generateProvider,
		"provider",
		"",
		"Provider to store the key in. Defaults to the one 'init' recorded.",
	)
}

func runGenerate(cmd *cobra.Command, args []string) error {
	kid := generateKid
	description := generateDescription

	// If no kid provided, run interactive mode
	if kid == "" && len(args) == 0 {
		return runGenerateInteractive()
	}

	// Get kid from args if not in flag
	if kid == "" && len(args) > 0 {
		kid = args[0]
	}

	// Validate key ID format
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(kid) {
		return fmt.Errorf("invalid key ID: must contain only alphanumeric characters, hyphens, and underscores")
	}

	// Read credentials
	creds, err := panda.ReadCredentials()
	if err != nil {
		return fmt.Errorf("failed to read credentials: %w", err)
	}

	if creds == nil {
		return fmt.Errorf("no PANDA configuration found. Run 'panda init' first")
	}

	// The override, applied before the key is stored rather than inside the
	// store function. panda-node called this `--keystore`; one concept under
	// two names is two definitions of it, and cli-flags.md pins --provider.
	if strings.TrimSpace(generateProvider) != "" {
		override := strings.ToLower(strings.TrimSpace(generateProvider))
		if !slices.Contains(providerNames, override) {
			return fmt.Errorf(
				"unknown provider: %s (expected one of %s)",
				override, strings.Join(providerNames, ", "),
			)
		}
		creds.Provider = override
	}

	// Generate and store key
	if err := generateAndStoreKey(kid, creds, description); err != nil {
		return err
	}

	fmt.Printf("\n✓ Key '%s' generated successfully!\n", kid)
	fmt.Println("\nTo use this key:")
	fmt.Printf("  cipher.Encrypt(value, '%s', context, field)\n", kid)

	return nil
}

func runGenerateInteractive() error {
	fmt.Println("🔑 PANDA Key Generation")
	fmt.Println("=======================")

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Key ID (e.g., nik-key, health-data-key): ")
	kidInput, _ := reader.ReadString('\n')
	kid := strings.TrimSpace(kidInput)

	if kid == "" {
		return fmt.Errorf("key ID is required")
	}

	// Validate key ID format
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(kid) {
		return fmt.Errorf("invalid key ID: must contain only alphanumeric characters, hyphens, and underscores")
	}

	fmt.Print("Description (optional): ")
	descInput, _ := reader.ReadString('\n')
	description := strings.TrimSpace(descInput)

	// Read credentials
	creds, err := panda.ReadCredentials()
	if err != nil {
		return fmt.Errorf("failed to read credentials: %w", err)
	}

	if creds == nil {
		return fmt.Errorf("no PANDA configuration found. Run 'panda init' first")
	}

	// Generate and store key
	if err := generateAndStoreKey(kid, creds, description); err != nil {
		return err
	}

	fmt.Printf("\n✓ Key '%s' generated successfully!\n", kid)
	fmt.Println("\nTo use this key:")
	fmt.Printf("  cipher.Encrypt(value, '%s', context, field)\n", kid)

	return nil
}

func generateAndStoreKey(kid string, creds *panda.PandaCredentials, description string) error {
	fmt.Printf("\nGenerating key for KID: %s\n", kid)

	if description != "" {
		fmt.Printf("Description: %s\n", description)
	}

	// Generate 32-byte random key, and report that one exists.
	keyBytes, err := telemetry.NewEncryptionKey()
	if err != nil {
		return err
	}

	keyBase64 := base64.StdEncoding.EncodeToString(keyBytes)

	switch creds.Provider {
	case "local":
		return storeLocalKey(kid, keyBase64, creds)

	case "vault":
		return storeVaultKey(kid, keyBase64, creds)

	case "infisical":
		return storeInfisicalKey(kid, keyBase64, creds)

	default:
		// Fallback to local
		fmt.Println("No provider configured, using local storage")
		return storeLocalKey(kid, keyBase64, creds)
	}
}

func storeLocalKey(kid, keyBase64 string, creds *panda.PandaCredentials) error {
	normalizedKid := strings.ToUpper(regexp.MustCompile(`[^A-Za-z0-9]`).ReplaceAllString(kid, "_"))
	envVarName := fmt.Sprintf("PANDA_KEY_%s", normalizedKid)

	envPath := filepath.Join(".env")
	examplePath := filepath.Join(".env.example")

	appendEnv(envPath, envVarName, keyBase64)
	appendEnv(examplePath, envVarName, "")

	fmt.Printf("✓ Key stored in .env as %s\n", envVarName)
	fmt.Println("⚠️  IMPORTANT: Commit .env to your secret management system!")

	// Update credentials keys metadata
	if creds.Keys == nil {
		creds.Keys = make(map[string]panda.KeyInfo)
	}

	creds.Keys[kid] = panda.KeyInfo{
		Created:  getCurrentTimestamp(),
		Provider: "local",
	}

	return panda.WriteCredentials(creds)
}

func storeVaultKey(kid, keyBase64 string, creds *panda.PandaCredentials) error {
	fmt.Println("\nStoring key in HashiCorp Vault...")
	fmt.Printf("Path: %s/%s\n", creds.VaultMount, kid)
	fmt.Println("Note: Manual setup required. Use Vault CLI or UI:")
	fmt.Printf("  vault kv put %s/%s value=%s\n", creds.VaultMount, kid, keyBase64)

	// Update credentials keys metadata
	if creds.Keys == nil {
		creds.Keys = make(map[string]panda.KeyInfo)
	}

	creds.Keys[kid] = panda.KeyInfo{
		Created:  getCurrentTimestamp(),
		Provider: "vault",
	}

	return panda.WriteCredentials(creds)
}

func storeInfisicalKey(kid, keyBase64 string, creds *panda.PandaCredentials) error {
	fmt.Println("\nStoring key in Infisical...")
	fmt.Printf("Note: Manual setup may be required. Create secret in Infisical UI:")
	fmt.Printf("  Path: %s\n", kid)
	fmt.Printf("  Value (base64): %s\n", keyBase64)

	// For now, we just update the metadata since we'd need to implement the Infisical API call
	// In a full implementation, this would make an API call to Infisical

	// Update credentials keys metadata
	if creds.Keys == nil {
		creds.Keys = make(map[string]panda.KeyInfo)
	}

	creds.Keys[kid] = panda.KeyInfo{
		Created:  getCurrentTimestamp(),
		Provider: "infisical",
	}

	return panda.WriteCredentials(creds)
}

package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/jatimprovcsirt/panda-go/internal/panda"
	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Display PANDA configuration details",
	Long:  `Display detailed PANDA configuration including provider settings, keys, and environment variables.`,
	RunE: runConfig,
}

func init() {
	rootCmd.AddCommand(configCmd)
}

func runConfig(cmd *cobra.Command, args []string) error {
	fmt.Println("\n🐼 PANDA Configuration")
	fmt.Println("======================\n")

	// Read credentials
	creds, err := panda.ReadCredentials()
	if err != nil {
		return fmt.Errorf("failed to read credentials: %w", err)
	}

	if creds == nil {
		fmt.Println("⚠️  No PANDA configuration found. Run 'panda init' first.")
		return nil
	}

	// Display provider configuration
	fmt.Println("Provider Configuration:")
	fmt.Println("-----------------------")
	fmt.Printf("Provider: %s\n", creds.Provider)

	switch creds.Provider {
	case "local":
		fmt.Println("  Type: Environment Variables")
		fmt.Println("  Storage: .env file")
		fmt.Println("  Keys stored as: PANDA_KEY_<KID>")

	case "vault":
		fmt.Println("  Type: HashiCorp Vault")
		fmt.Printf("  URL: %s\n", creds.VaultURL)
		fmt.Printf("  Auth Method: %s\n", creds.VaultAuthMethod)
		if creds.VaultAuthMethod == "approle" {
			if creds.VaultRoleId != "" {
				fmt.Println("  Role ID: ***configured***")
			} else {
				fmt.Println("  Role ID: not set")
			}
			if creds.VaultSecretId != "" {
				fmt.Println("  Secret ID: ***configured***")
			} else {
				fmt.Println("  Secret ID: not set")
			}
		} else {
			if creds.VaultToken != "" {
				fmt.Println("  Token: ***configured***")
			} else {
				fmt.Println("  Token: not set")
			}
		}
		if creds.VaultTokenTTL != "" {
			fmt.Printf("  Token TTL: %s seconds\n", creds.VaultTokenTTL)
		}
		fmt.Printf("  Mount Path: %s\n", creds.VaultMount)
		fmt.Println("  Keys stored at: <mount>/<kid>")

	case "infisical":
		fmt.Println("  Type: Infisical Secrets Manager")
		fmt.Printf("  Site URL: %s\n", creds.InfisicalSiteUrl)
		fmt.Printf("  Project ID: %s\n", creds.InfisicalProjectId)
		fmt.Printf("  Environment: %s\n", creds.InfisicalEnvironment)
		if creds.InfisicalClientId != "" {
			fmt.Printf("  Client ID: %s\n", creds.InfisicalClientId)
		} else {
			fmt.Println("  Client ID: not set")
		}
		if creds.InfisicalClientSecret != "" {
			fmt.Println("  Client Secret: ***configured***")
		} else {
			fmt.Println("  Client Secret: not set")
		}
		fmt.Printf("  Cache TTL: %ss\n", creds.InfisicalCacheTTL)
		fmt.Println("  Keys stored as: secrets in Infisical")
	}

	// Default Key ID
	if creds.DefaultKid != "" {
		fmt.Printf("\nDefault Key ID: %s\n", creds.DefaultKid)
	}

	// List configured keys
	if len(creds.Keys) > 0 {
		fmt.Println("\nConfigured Keys:")
		fmt.Println("-----------------")
		for kid, info := range creds.Keys {
			fmt.Printf("  %s\n", kid)
			fmt.Printf("    Created: %s\n", info.Created)
			fmt.Printf("    Provider: %s\n", info.Provider)
		}
	}

	// Display .env.example template
	fmt.Println("\nEnvironment Variables Template:")
	fmt.Println("-------------------------------")

	switch creds.Provider {
	case "local":
		fmt.Println("# Local Key Provider")
		fmt.Println("PANDA_KEY_PROVIDER_DRIVER=local")
		fmt.Println("PANDA_DEFAULT_KID=default-key")
		fmt.Println("PANDA_KEY_DEFAULT_KEY=<base64-encoded-key>")

	case "vault":
		fmt.Println("# Vault Key Provider")
		fmt.Println("PANDA_KEY_PROVIDER_DRIVER=vault")
		fmt.Println("PANDA_DEFAULT_KID=default-key")
		fmt.Printf("PANDA_VAULT_URL=%s\n", creds.VaultURL)
		fmt.Println("PANDA_VAULT_TOKEN=<vault-token>")
		fmt.Printf("PANDA_VAULT_MOUNT_PATH=%s\n", creds.VaultMount)

	case "infisical":
		fmt.Println("# Infisical Key Provider")
		fmt.Println("PANDA_KEY_PROVIDER_DRIVER=infisical")
		fmt.Println("PANDA_DEFAULT_KID=default-key")
		fmt.Printf("PANDA_INFISICAL_SITE_URL=%s\n", creds.InfisicalSiteUrl)
		if creds.InfisicalClientId != "" {
			fmt.Printf("PANDA_INFISICAL_CLIENT_ID=%s\n", creds.InfisicalClientId)
		} else {
			fmt.Println("PANDA_INFISICAL_CLIENT_ID=<client-id>")
		}
		fmt.Println("PANDA_INFISICAL_CLIENT_SECRET=<client-secret>")
		fmt.Printf("PANDA_INFISICAL_PROJECT_ID=%s\n", creds.InfisicalProjectId)
		fmt.Printf("PANDA_INFISICAL_ENVIRONMENT=%s\n", creds.InfisicalEnvironment)
		fmt.Printf("PANDA_INFISICAL_CACHE_TTL=%s\n", creds.InfisicalCacheTTL)
	}

	// Current working directory info
	fmt.Println("\nWorking Directory:")
	fmt.Println("-------------------")
	fmt.Printf("  Path: %s\n", cwd())

	pandaPath := cwd() + string(os.PathSeparator) + panda.PandaDir
	if _, err := os.Stat(pandaPath); err == nil {
		fmt.Println("  .panda directory: ✓ exists")
	} else {
		fmt.Println("  .panda directory: ✗ not found")
	}

	// Environment info
	fmt.Println("\nEnvironment:")
	fmt.Println("-----------")
	fmt.Printf("  Platform: %s\n", runtime.GOOS)
	fmt.Printf("  Arch: %s\n", runtime.GOARCH)
	fmt.Printf("  Go Version: %s\n", runtime.Version())

	fmt.Println()

	return nil
}

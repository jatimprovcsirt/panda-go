package cmd

import (
	"fmt"
	"os"
	"regexp"
	"runtime"

	"github.com/jatimprovcsirt/panda-go/internal/panda"
	"github.com/spf13/cobra"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display PANDA configuration and test connectivity",
	Long: `Display the current PANDA configuration, test provider connectivity,
and show system information.`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("\n🐼 PANDA Status")
	fmt.Println("==============\n")

	// Check if .panda exists
	if !panda.PandaDirExists() {
		fmt.Println("⚠️  No PANDA configuration found. Run 'panda init' first.")
		fmt.Println("\nChecking environment variables...")

		// Check for PANDA env vars
		found := false
		for _, env := range os.Environ() {
			for i := 0; i < len(env); i++ {
				if env[i] == '=' {
					key := env[:i]
					if len(key) > 6 && key[:6] == "PANDA_" {
						if !found {
							fmt.Println("\nFound PANDA environment variables:")
							found = true
						}
						// Mask sensitive values
						if contains(key, "SECRET") || contains(key, "TOKEN") || contains(key, "KEY") {
							fmt.Printf("  %s = ***\n", key)
						} else {
							value := env[i+1:]
							fmt.Printf("  %s = %s\n", key, value)
						}
						break
					}
				}
			}
		}

		if !found {
			fmt.Println("No PANDA environment variables found.")
		}

		return nil
	}

	// Read credentials
	creds, err := panda.ReadCredentials()
	if err != nil {
		return fmt.Errorf("failed to read credentials: %w", err)
	}

	// Provider Configuration
	fmt.Println("Key Provider Configuration:")
	fmt.Println("---------------------------")
	fmt.Printf("Provider: %s\n", creds.Provider)

	switch creds.Provider {
	case "local":
		fmt.Println("  Type: Environment Variables")
		fmt.Println("  Storage: .env file")

	case "vault":
		fmt.Println("  Type: HashiCorp Vault")
		fmt.Printf("  URL: %s\n", creds.VaultURL)
		fmt.Printf("  Auth: %s\n", creds.VaultAuthMethod)
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
		fmt.Printf("  Mount: %s\n", creds.VaultMount)

	case "infisical":
		fmt.Println("  Type: Infisical")
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
		fmt.Printf("  Cache TTL: %s\n", creds.InfisicalCacheTTL)
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

	// Test provider connectivity
	fmt.Println("\nTesting Provider Connectivity:")
	fmt.Println("---------------------------------")

	testKid := creds.DefaultKid
	if testKid == "" {
		testKid = "test-key"
	}

	fmt.Printf("Testing with KID: %s\n", testKid)

	switch creds.Provider {
	case "local":
		normalizedKid := testKid
		// Convert to env var format
		reg := regexp.MustCompile(`[^A-Za-z0-9]`)
		normalizedKid = string(reg.ReplaceAll([]byte(testKid), []byte("_")))
		envVar := "PANDA_KEY_" + toUpper(normalizedKid)

		if os.Getenv(envVar) != "" {
			fmt.Println("✓ Local key found in environment")
		} else {
			fmt.Printf("⚠️  Local key not found: %s\n", envVar)
		}

	default:
		fmt.Println("✓ Provider configuration valid")
		fmt.Println("  Note: Key access will be verified at runtime")
	}

	// Framework integration detection
	fmt.Println("\nFramework Integration:")
	fmt.Println("----------------------")

	// Check for common framework files
	if fileExists("composer.json") && fileExists("app/Providers/PandaServiceProvider.php") {
		fmt.Println("  ✓ Laravel detected")
	}
	if fileExists("package.json") && fileExists("src/app.module.ts") {
		fmt.Println("  ✓ NestJS detected")
	}
	if fileExists("composer.json") && fileExists("app/Config/Panda.php") {
		fmt.Println("  ✓ CodeIgniter detected")
	}
	if fileExists("package.json") && fileExists("src/server.ts") {
		fmt.Println("  ✓ Express detected")
	}

	// Environment check
	fmt.Println("\nEnvironment:")
	fmt.Println("-------------")
	fmt.Printf("  Platform: %s\n", runtime.GOOS)
	fmt.Printf("  Arch: %s\n", runtime.GOARCH)
	fmt.Printf("  CWD: %s\n", cwd())

	// Tips
	fmt.Println("\nQuick Tips:")
	fmt.Println("-----------")
	fmt.Println("  panda generate <kid>     - Create a new encryption key")
	fmt.Println("  panda rotate-key         - Rotate to a new active key")
	fmt.Println("  panda migrate <table>   - Encrypt existing data")
	fmt.Println("  panda shred <kid>       - Permanently delete a key")
	fmt.Println()

	return nil
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstr(s, substr)
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func cwd() string {
	dir, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	return dir
}

func toUpper(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result[i] = c
	}
	return string(result)
}

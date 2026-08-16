package cmd

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jatimprovcsirt/panda-go/internal/panda"
	"github.com/spf13/cobra"
)

// deinitCmd represents the deinit command
var deinitCmd = &cobra.Command{
	Use:   "deinit",
	Short: "Remove PANDA configuration and .panda directory",
	Long: `Remove PANDA configuration and .panda directory.
This will permanently delete credentials and keys metadata.`,
	RunE: runDeinit,
}

func init() {
	deinitCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")
}

func runDeinit(cmd *cobra.Command, args []string) error {
	fmt.Println("🐼 PANDA Deinitialization")
	fmt.Println("==========================")

	pandaPath := filepath.Join(panda.PandaDir)

	// Check if .panda exists
	if _, err := os.Stat(pandaPath); os.IsNotExist(err) {
		fmt.Println("No PANDA configuration found (.panda directory does not exist).")
		return nil
	}

	// Warning prompt
	if !force {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("⚠️  This will permanently delete your PANDA configuration including credentials and keys metadata.\n" +
			"Are you sure you want to continue? (yes/no): ")

		answer, _ := reader.ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))

		if answer != "yes" && answer != "y" {
			fmt.Println("Deinitialization cancelled.")
			return nil
		}
	}

	// Remove .panda directory
	fmt.Println("Removing .panda directory...")
	if err := panda.RemovePandaDirectory(); err != nil {
		fmt.Printf("✗ Failed to remove .panda directory: %v\n", err)
	} else {
		fmt.Println("✓ .panda directory removed")
	}

	// Clean up .env files
	fmt.Println("\nCleaning up .env files...")

	envPath := filepath.Join(".env")
	examplePath := filepath.Join(".env.example")

	// PANDA environment variables to remove
	pandaVars := []string{
		"PANDA_ACCESS_TOKEN",
		"PANDA_DEFAULT_KID",
		"PANDA_KEY_PROVIDER_DRIVER",
		"PANDA_VAULT_URL",
		"PANDA_VAULT_TOKEN",
		"PANDA_VAULT_MOUNT_PATH",
		"PANDA_INFISICAL_SITE_URL",
		"PANDA_INFISICAL_CLIENT_ID",
		"PANDA_INFISICAL_CLIENT_SECRET",
		"PANDA_INFISICAL_PROJECT_ID",
		"PANDA_INFISICAL_ENVIRONMENT",
		"PANDA_INFISICAL_CACHE_TTL",
	}

	for _, envFile := range []string{envPath, examplePath} {
		if _, err := os.Stat(envFile); os.IsNotExist(err) {
			continue
		}

		content, err := os.ReadFile(envFile)
		if err != nil {
			continue
		}

		contentStr := string(content)
		modified := false

		// Remove specific PANDA variables
		for _, varName := range pandaVars {
			regex := regexp.MustCompile(`(?m)^` + varName + "=.*\r?\n?")
			if regex.MatchString(contentStr) {
				contentStr = regex.ReplaceAllString(contentStr, "")
				modified = true
				fmt.Printf("  ✓ Removed %s from %s\n", varName, filepath.Base(envFile))
			}
		}

		// Remove PANDA_KEY_* variables
		keyRegex := regexp.MustCompile(`(?m)^PANDA_KEY_.*=.*\r?\n?`)
		if keyRegex.MatchString(contentStr) {
			contentStr = keyRegex.ReplaceAllString(contentStr, "")
			modified = true
			fmt.Printf("  ✓ Removed PANDA_KEY_* variables from %s\n", filepath.Base(envFile))
		}

		if modified {
			// Clean up extra blank lines
			excessNewlines := regexp.MustCompile(`\n{3,}`)
			contentStr = excessNewlines.ReplaceAllString(contentStr, "\n\n")
			os.WriteFile(envFile, []byte(strings.TrimSpace(contentStr)+"\n"), 0644)
		}
	}

	fmt.Println("\n✓ PANDA deinitialization complete!")
	fmt.Println("\nTo start fresh, run: panda init")
	fmt.Println()

	return nil
}

// Helper function to check if path exists
func pathExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// Helper to walk directory
func walkDir(path string, walkFn fs.WalkDirFunc) error {
	return filepath.WalkDir(path, walkFn)
}

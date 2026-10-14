package cmd

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jatimprovcsirt/panda-go/crypto"
	"github.com/jatimprovcsirt/panda-go/internal/panda"
	"github.com/spf13/cobra"
)

var (
	initToken    string
	initKid      string
	initQuick    bool
	initReinit   bool
	initSkipKey  bool
	initProvider string
)

// providerNames are the values --provider accepts.
//
// Exported to the tests through the package rather than written out again
// there. A test that restates a rule asserts its own copy of it — which is how
// the token pattern's second copy here survived a release, in this package.
var providerNames = []string{"local", "vault", "infisical"}

// The environment variables each provider is configured from on the
// non-interactive path. These are the names VaultKeyProvider,
// InfisicalKeyProvider and CLAUDE.md's environment reference already use.
var (
	vaultRequiredEnv     = []string{"PANDA_VAULT_URL"}
	vaultApproleEnv      = []string{"PANDA_VAULT_ROLE_ID", "PANDA_VAULT_SECRET_ID"}
	infisicalRequiredEnv = []string{
		"PANDA_INFISICAL_CLIENT_ID",
		"PANDA_INFISICAL_CLIENT_SECRET",
		"PANDA_INFISICAL_PROJECT_ID",
	}
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize PANDA with interactive wizard",
	Long: `Initialize PANDA with an interactive wizard that guides you through:
- Authentication token validation
- Key provider selection (local, vault, or infisical)
- Configuration setup
- First key generation

Use --quick flag for non-interactive local setup.`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initToken, "token", "", "Per-application access token")
	// Quick mode took no key identifier at all, so it always produced
	// `default-key` — the one flag panda-node and panda-php both accept on
	// `init --quick` was missing here, and a command that works in two SDKs
	// and errors in a third is a documented workflow that is wrong for
	// whoever picked this one. Later keys are `panda generate <kid>` in every
	// SDK; this is the first key.
	initCmd.Flags().StringVar(&initKid, "kid", "default-key", "Key Identifier (quick mode)")
	initCmd.Flags().BoolVar(&initQuick, "quick", false, "Skip the wizard; non-interactive setup")
	initCmd.Flags().BoolVar(&initReinit, "reinit", false, "Reinitialize even if already initialized")
	initCmd.Flags().BoolVar(&initSkipKey, "skip-key-gen", false, "Skip first key generation")
	initCmd.Flags().StringVar(
		&initProvider,
		"provider",
		"",
		"Key provider: local, vault, or infisical. Implies non-interactive, as --quick does.",
	)
}

func runInit(cmd *cobra.Command, args []string) error {
	// Check if already initialized
	if panda.PandaDirExists() && !initReinit {
		fmt.Println("PANDA is already initialized.")
		fmt.Println("Use --reinit to reinitialize.")
		return nil
	}

	// Naming a provider implies the non-interactive path for the same reason
	// --quick does: it is an instruction the wizard cannot accept, since it
	// would ask the question anyway and discard the answer. panda-node has
	// read it this way since it gained the flag, so reading it otherwise here
	// would introduce a disagreement in the course of removing one.
	if initQuick || strings.TrimSpace(initProvider) != "" {
		return runQuickInit(initProvider)
	}

	return runWizard()
}

func runQuickInit(provider string) error {
	fmt.Println("🐼 PANDA Quick Init")
	fmt.Println("====================")

	token := initToken
	if token == "" {
		token = os.Getenv("PANDA_ACCESS_TOKEN")
	}

	// Validate token
	if err := crypto.ValidateToken(token); err != nil {
		return fmt.Errorf("token gate failed: %w", err)
	}

	if crypto.IsDemoToken(token) && !crypto.IsLocalEnvironment() {
		fmt.Println("⚠️  WARNING: You are using the static DEMO TOKEN outside a local development environment.")
		fmt.Println("Please register your application at the PANDA portal to obtain a per-application live token.")
	}

	fmt.Println("✓ Token validated")

	// Same handling as the wizard: empty falls back to default-key, and the
	// value is carried through unchanged to the config and the credentials.
	// generateAndStoreKey normalizes it separately for the environment
	// variable name.
	kid := strings.TrimSpace(initKid)
	if kid == "" {
		kid = "default-key"
	}

	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "local"
	}
	if !slices.Contains(providerNames, provider) {
		return fmt.Errorf(
			"unknown provider: %s (expected one of %s)",
			provider, strings.Join(providerNames, ", "),
		)
	}

	creds := &panda.PandaCredentials{
		Token:      token,
		Provider:   provider,
		DefaultKid: kid,
	}

	// Provider configuration is resolved before anything is written, so a
	// short environment stops init with nothing left behind.
	if provider != "local" {
		if err := applyProviderEnv(creds, provider); err != nil {
			return err
		}
	}

	// Create .panda directory
	if err := panda.CreatePandaDirectory(); err != nil {
		return fmt.Errorf("failed to create .panda directory: %w", err)
	}

	if err := panda.WriteCredentials(creds); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	// Write config
	config := &panda.PandaConfig{
		Version:     "1.0.0",
		Initialized: getCurrentTimestamp(),
		Provider:    panda.ProviderConfig{Type: provider},
		DefaultKid:  kid,
	}

	if err := panda.WriteConfig(config); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Generate default key. Only for the local provider: a key generated
	// "for" Vault or Infisical is a second key that nothing reads, and
	// panda-node generates none on this path either.
	if !initSkipKey && provider == "local" {
		if err := generateAndStoreKey(kid, creds, "Default PANDA key"); err != nil {
			return err
		}
	}

	fmt.Println("\n✓ PANDA initialized successfully!")
	fmt.Println("Run 'panda status' to verify configuration.")

	return nil
}

// applyProviderEnv fills a non-local provider's settings from the
// environment, or returns an error naming what is missing.
//
// Fail-closed, as the token gate on this path is. The wizard may offer
// http://127.0.0.1:8200 as a default because a person is there to see it and
// disagree; --quick cannot ask, and a credentials file naming a Vault that
// nothing said to use behaves like a working configuration until the first
// decrypt.
func applyProviderEnv(creds *panda.PandaCredentials, provider string) error {
	if provider == "vault" {
		if err := requireEnv(vaultRequiredEnv, provider); err != nil {
			return err
		}

		method := os.Getenv("PANDA_VAULT_AUTH_METHOD")
		if method == "" {
			// Inferred where it is unambiguous. Demanding the variable when
			// the caller has already answered the question by setting the role
			// and secret, or a token, is the difference between a quick init
			// that works and one that argues.
			if envAllSet(vaultApproleEnv) {
				method = "approle"
			} else if os.Getenv("PANDA_VAULT_TOKEN") != "" {
				method = "token"
			} else if err := requireEnv([]string{"PANDA_VAULT_AUTH_METHOD"}, provider); err != nil {
				return err
			}
		}

		if method != "approle" && method != "token" {
			return fmt.Errorf("PANDA_VAULT_AUTH_METHOD must be 'approle' or 'token', not %q", method)
		}

		creds.VaultURL = os.Getenv("PANDA_VAULT_URL")
		creds.VaultAuthMethod = method
		creds.VaultMount = envOr("PANDA_VAULT_MOUNT_PATH", "secret")

		if method == "approle" {
			if err := requireEnv(vaultApproleEnv, provider); err != nil {
				return err
			}
			creds.VaultRoleId = os.Getenv("PANDA_VAULT_ROLE_ID")
			creds.VaultSecretId = os.Getenv("PANDA_VAULT_SECRET_ID")
			creds.VaultTokenTTL = envOr("PANDA_VAULT_TOKEN_TTL", "3600")
		} else {
			if err := requireEnv([]string{"PANDA_VAULT_TOKEN"}, provider); err != nil {
				return err
			}
			creds.VaultToken = os.Getenv("PANDA_VAULT_TOKEN")
		}

		return nil
	}

	// infisical
	if err := requireEnv(infisicalRequiredEnv, provider); err != nil {
		return err
	}

	// The site URL and the cache TTL do have safe defaults — one is the public
	// service, the other a duration — so unlike the credentials above they are
	// defaulted rather than demanded.
	creds.InfisicalSiteUrl = envOr("PANDA_INFISICAL_SITE_URL", "https://app.infisical.com")
	creds.InfisicalClientId = os.Getenv("PANDA_INFISICAL_CLIENT_ID")
	creds.InfisicalClientSecret = os.Getenv("PANDA_INFISICAL_CLIENT_SECRET")
	creds.InfisicalProjectId = os.Getenv("PANDA_INFISICAL_PROJECT_ID")
	creds.InfisicalEnvironment = envOr("PANDA_INFISICAL_ENVIRONMENT", "dev")
	creds.InfisicalCacheTTL = envOr("PANDA_INFISICAL_CACHE_TTL", "300")

	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envAllSet(names []string) bool {
	for _, name := range names {
		if os.Getenv(name) == "" {
			return false
		}
	}
	return true
}

// requireEnv names every variable that is missing, not only the first. A
// refusal that says "Vault is not configured" sends the reader to the
// documentation; one that lists the variables sends them to their shell.
func requireEnv(names []string, provider string) error {
	absent := make([]string, 0, len(names))
	for _, name := range names {
		if os.Getenv(name) == "" {
			absent = append(absent, name)
		}
	}
	if len(absent) == 0 {
		return nil
	}

	verb := "It is"
	if len(absent) > 1 {
		verb = "These are"
	}

	return fmt.Errorf(
		"--provider %s needs %s to be set. %s read from the environment: "+
			"this path cannot ask, and defaulting would write a configuration nobody chose",
		provider, strings.Join(absent, " and "), verb,
	)
}

func runWizard() error {
	fmt.Println("🐼 PANDA Initialization Wizard")
	fmt.Println("==============================")

	reader := bufio.NewReader(os.Stdin)

	// Step 1: Authentication
	fmt.Println("Step 1: Authentication")
	fmt.Println("---------------------")

	token := initToken
	if token == "" {
		token = os.Getenv("PANDA_ACCESS_TOKEN")
	}

	if token == "" {
		fmt.Print("Enter your PANDA access token (or press Enter to skip): ")
		input, _ := reader.ReadString('\n')
		token = strings.TrimSpace(input)
	}

	if token != "" {
		// The pattern comes from the crypto package rather than being written
		// out again here. It was written out again, and the two had drifted:
		// this copy accepted 48 hex characters where crypto.TOKEN_PATTERN
		// accepts 48 or 64, so a token the rest of the tool considers valid
		// was rejected here.
		if !crypto.ValidateTokenFormat(token) {
			fmt.Println("⚠️  Warning: Token format appears invalid.")
			fmt.Print("Continue anyway? (y/n): ")
			input, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(input)) != "y" {
				fmt.Println("Initialization cancelled.")
				return nil
			}
		} else {
			fmt.Println("✓ Token format validated")
		}
	}

	// Create .panda directory
	if err := panda.CreatePandaDirectory(); err != nil {
		return fmt.Errorf("failed to create .panda directory: %w", err)
	}

	// Step 2: Select provider
	fmt.Println("\nStep 2: Key Provider Selection")
	fmt.Println("-------------------------------")
	fmt.Println("Where should encryption keys be stored?")
	fmt.Println("  1. Local (environment variables)")
	fmt.Println("  2. HashiCorp Vault")
	fmt.Println("  3. Infisical")

	fmt.Print("Enter choice (1-3) [default: 1]: ")
	input, _ := reader.ReadString('\n')
	choice := strings.TrimSpace(input)

	if choice == "" {
		choice = "1"
	}

	var creds *panda.PandaCredentials

	switch choice {
	case "2":
		creds = setupVault(reader, token)
	case "3":
		creds = setupInfisical(reader, token)
	default:
		creds = &panda.PandaCredentials{
			Token:    token,
			Provider: "local",
		}
	}

	// Step 3: Default Key ID
	fmt.Println("\nStep 3: Default Key Configuration")
	fmt.Println("------------------------------------")
	fmt.Print("Default Key ID [default: default-key]: ")
	kidInput, _ := reader.ReadString('\n')
	defaultKid := strings.TrimSpace(kidInput)
	if defaultKid == "" {
		defaultKid = "default-key"
	}

	creds.DefaultKid = defaultKid

	// Write credentials
	if err := panda.WriteCredentials(creds); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	// Write config
	config := &panda.PandaConfig{
		Version:     "1.0.0",
		Initialized: getCurrentTimestamp(),
		Provider:    panda.ProviderConfig{Type: creds.Provider},
		DefaultKid:  defaultKid,
	}

	if err := panda.WriteConfig(config); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Step 4: Generate key
	fmt.Println("\nStep 4: Key Generation")
	fmt.Println("----------------------")

	if !initSkipKey {
		if err := generateAndStoreKey(defaultKid, creds, "Default key from wizard"); err != nil {
			return err
		}
	}

	// Step 5: Framework selection
	fmt.Println("\nStep 5: Framework Integration")
	fmt.Println("-----------------------------")
	fmt.Println("Select your framework (for auto-configuration):")
	fmt.Println("  1. Laravel (PHP)")
	fmt.Println("  2. NestJS (Node.js)")
	fmt.Println("  3. CodeIgniter (PHP)")
	fmt.Println("  4. Express (Node.js)")
	fmt.Println("  5. None/Skip")

	fmt.Print("Enter choice (1-5) [default: 5]: ")
	fwInput, _ := reader.ReadString('\n')
	fwChoice := strings.TrimSpace(fwInput)

	switch fwChoice {
	case "1":
		printLaravelInstructions(creds, defaultKid)
	case "2":
		printNestJSInstructions(creds, defaultKid)
	default:
		break
	}

	fmt.Println("\n✓ PANDA initialization complete!")
	fmt.Println("\nNext steps:")
	fmt.Println("  - Use 'panda generate <kid>' to create encryption keys")
	fmt.Println("  - Use 'panda status' to verify configuration")
	fmt.Println("  - Use 'panda migrate' to encrypt existing data")

	return nil
}

func setupVault(reader *bufio.Reader, token string) *panda.PandaCredentials {
	fmt.Println("\nConfiguring HashiCorp Vault...")

	fmt.Print("Vault URL [default: http://127.0.0.1:8200]: ")
	urlInput, _ := reader.ReadString('\n')
	vaultURL := strings.TrimSpace(urlInput)
	if vaultURL == "" {
		vaultURL = "http://127.0.0.1:8200"
	}

	// Authentication method selection
	fmt.Println("\nSelect Vault authentication method:")
	fmt.Println("  1. AppRole (Recommended - Auto-renewal, production-ready)")
	fmt.Println("  2. Token (Advanced - Manual renewal)")
	fmt.Print("Choose method [default: 1]: ")
	authInput, _ := reader.ReadString('\n')
	authChoice := strings.TrimSpace(authInput)
	if authChoice == "" {
		authChoice = "1"
	}

	var vaultAuthMethod string
	var vaultToken string
	var vaultRoleId string
	var vaultSecretId string
	var vaultTokenTTL string

	if authChoice == "1" {
		// AppRole authentication
		vaultAuthMethod = "approle"
		fmt.Println("\nUsing AppRole authentication (auto-renewal enabled)")

		fmt.Print("Role ID: ")
		roleIdInput, _ := reader.ReadString('\n')
		vaultRoleId = strings.TrimSpace(roleIdInput)

		fmt.Print("Secret ID: ")
		secretIdInput, _ := reader.ReadString('\n')
		vaultSecretId = strings.TrimSpace(secretIdInput)

		// Optional: Token TTL
		fmt.Println("\nToken TTL (Optional)")
		fmt.Println("  Token lifetime before auto-renewal. Default: 3600s (1 hour)")
		fmt.Println("  Press Enter to use default, or enter custom value (300-86400 seconds)")
		fmt.Print("Token TTL in seconds [default: 3600]: ")
		ttlInput, _ := reader.ReadString('\n')
		vaultTokenTTL = strings.TrimSpace(ttlInput)
		if vaultTokenTTL == "" {
			vaultTokenTTL = "3600"
		}
	} else {
		// Token authentication
		vaultAuthMethod = "token"
		fmt.Println("\nUsing Token authentication (manual renewal required)")

		fmt.Print("Vault Token: ")
		tokenInput, _ := reader.ReadString('\n')
		vaultToken = strings.TrimSpace(tokenInput)
		vaultTokenTTL = "3600" // Default for token auth
	}

	fmt.Print("Mount path [default: secret]: ")
	mountInput, _ := reader.ReadString('\n')
	vaultMount := strings.TrimSpace(mountInput)
	if vaultMount == "" {
		vaultMount = "secret"
	}

	return &panda.PandaCredentials{
		Token:           token,
		Provider:        "vault",
		VaultURL:        vaultURL,
		VaultAuthMethod: vaultAuthMethod,
		VaultToken:      vaultToken,
		VaultRoleId:     vaultRoleId,
		VaultSecretId:   vaultSecretId,
		VaultTokenTTL:   vaultTokenTTL,
		VaultMount:      vaultMount,
	}
}

func setupInfisical(reader *bufio.Reader, token string) *panda.PandaCredentials {
	fmt.Println("\nConfiguring Infisical...")

	fmt.Print("Infisical Site URL [default: https://app.infisical.com]: ")
	urlInput, _ := reader.ReadString('\n')
	siteURL := strings.TrimSpace(urlInput)
	if siteURL == "" {
		siteURL = "https://app.infisical.com"
	}

	fmt.Print("Machine Identity Client ID: ")
	clientIdInput, _ := reader.ReadString('\n')
	clientId := strings.TrimSpace(clientIdInput)

	fmt.Print("Machine Identity Client Secret: ")
	secretInput, _ := reader.ReadString('\n')
	clientSecret := strings.TrimSpace(secretInput)

	fmt.Print("Project ID: ")
	projectIdInput, _ := reader.ReadString('\n')
	projectId := strings.TrimSpace(projectIdInput)

	fmt.Print("Environment [default: dev]: ")
	envInput, _ := reader.ReadString('\n')
	environment := strings.TrimSpace(envInput)
	if environment == "" {
		environment = "dev"
	}

	fmt.Print("Cache TTL in seconds [default: 300]: ")
	ttlInput, _ := reader.ReadString('\n')
	cacheTTL := strings.TrimSpace(ttlInput)
	if cacheTTL == "" {
		cacheTTL = "300"
	}

	return &panda.PandaCredentials{
		Token:                 token,
		Provider:              "infisical",
		InfisicalSiteUrl:      siteURL,
		InfisicalClientId:     clientId,
		InfisicalClientSecret: clientSecret,
		InfisicalProjectId:    projectId,
		InfisicalEnvironment:  environment,
		InfisicalCacheTTL:     cacheTTL,
	}
}

func printLaravelInstructions(creds *panda.PandaCredentials, defaultKid string) {
	fmt.Println("\nFor Laravel, add these to your .env:")
	fmt.Printf("PANDA_KEY_PROVIDER_DRIVER=%s\n", creds.Provider)
	fmt.Printf("PANDA_DEFAULT_KID=%s\n", defaultKid)

	if creds.Provider == "vault" {
		fmt.Printf("PANDA_VAULT_URL=%s\n", creds.VaultURL)
		fmt.Printf("PANDA_VAULT_TOKEN=%s\n", creds.VaultToken)
		fmt.Printf("PANDA_VAULT_MOUNT_PATH=%s\n", creds.VaultMount)
	} else if creds.Provider == "infisical" {
		fmt.Printf("PANDA_INFISICAL_SITE_URL=%s\n", creds.InfisicalSiteUrl)
		fmt.Printf("PANDA_INFISICAL_CLIENT_ID=%s\n", creds.InfisicalClientId)
		fmt.Printf("PANDA_INFISICAL_CLIENT_SECRET=***\n")
		fmt.Printf("PANDA_INFISICAL_PROJECT_ID=%s\n", creds.InfisicalProjectId)
		fmt.Printf("PANDA_INFISICAL_ENVIRONMENT=%s\n", creds.InfisicalEnvironment)
	}
}

func printNestJSInstructions(creds *panda.PandaCredentials, defaultKid string) {
	fmt.Println("\nFor NestJS, use PandaModule.forRoot() in your app.module.ts:")
	fmt.Println("PandaModule.forRoot({")
	fmt.Printf("  keyProvider: '%s',\n", creds.Provider)
	if creds.Provider == "infisical" {
		fmt.Println("  infisical: {")
		fmt.Printf("    siteUrl: '%s',\n", creds.InfisicalSiteUrl)
		fmt.Printf("    clientId: '%s',\n", creds.InfisicalClientId)
		fmt.Println("    clientSecret: '***',")
		fmt.Printf("    projectId: '%s',\n", creds.InfisicalProjectId)
		fmt.Printf("    environment: '%s'\n", creds.InfisicalEnvironment)
		fmt.Println("  }")
	}
	fmt.Println("})")
}

func getCurrentTimestamp() string {
	return time.Now().Format(time.RFC3339)
}

package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/jatimprovcsirt/panda-go/crypto"
	"github.com/jatimprovcsirt/panda-go/internal/panda"
)

// `--provider` on the non-interactive path.
//
// panda-node had this flag and the other three did not, so `init --quick` here
// could only ever configure a local provider: Vault and Infisical were
// unreachable from a CI pipeline in three of the four SDKs. The flag set is
// pinned in panda-spec/cli-flags.md and checked by verify_interop.js.
//
// The variable names come from this package's own slices rather than being
// written out again. A test that restates a rule asserts its own copy of it —
// which is how the token pattern's second copy in this package survived a
// release, in a test that compiled its own regexp.

// providerVars is every variable these tests must clear, derived from the
// implementation's own lists.
func providerVars() []string {
	names := []string{"PANDA_VAULT_AUTH_METHOD", "PANDA_VAULT_TOKEN", "PANDA_VAULT_MOUNT_PATH", "PANDA_VAULT_TOKEN_TTL"}
	names = append(names, vaultRequiredEnv...)
	names = append(names, vaultApproleEnv...)
	names = append(names, infisicalRequiredEnv...)
	names = append(names,
		"PANDA_INFISICAL_SITE_URL",
		"PANDA_INFISICAL_ENVIRONMENT",
		"PANDA_INFISICAL_CACHE_TTL",
	)
	return names
}

// setupProviderTest clears the environment, isolates the working directory,
// and returns the directory. Every test states the environment it needs.
func setupProviderTest(t *testing.T) string {
	t.Helper()

	for _, name := range providerVars() {
		t.Setenv(name, "")
	}

	t.Chdir(t.TempDir())

	initToken = crypto.DEMO_TOKEN
	initKid = "k1"
	initSkipKey = false
	initProvider = ""
	t.Cleanup(func() {
		initToken = ""
		initKid = "default-key"
		initSkipKey = false
		initProvider = ""
	})

	return t.TempDir()
}

func readCredentialsOrFail(t *testing.T) *panda.PandaCredentials {
	t.Helper()
	creds, err := panda.ReadCredentials()
	if err != nil {
		t.Fatalf("ReadCredentials() error = %v", err)
	}
	if creds == nil {
		t.Fatal("ReadCredentials() returned nil")
	}
	return creds
}

func TestInitOffersTheProviderFlag(t *testing.T) {
	if initCmd.Flags().Lookup("provider") == nil {
		t.Error("init does not offer --provider")
	}
	if generateCmd.Flags().Lookup("provider") == nil {
		t.Error("generate does not offer --provider")
	}
}

func TestQuickInitRefusesAnUnknownProvider(t *testing.T) {
	setupProviderTest(t)

	err := runQuickInit("kerberos")
	if err == nil {
		t.Fatal("runQuickInit accepted an unknown provider")
	}
	if !strings.Contains(err.Error(), "kerberos") {
		t.Errorf("refusal does not name the provider: %v", err)
	}
	if panda.PandaDirExists() {
		t.Error("wrote a configuration it could not complete")
	}
}

func TestQuickInitVaultFailsClosedWithoutItsVariables(t *testing.T) {
	setupProviderTest(t)

	err := runQuickInit("vault")
	if err == nil {
		t.Fatal("runQuickInit succeeded with no Vault environment")
	}
	if !strings.Contains(err.Error(), vaultRequiredEnv[0]) {
		t.Errorf("refusal does not name %s: %v", vaultRequiredEnv[0], err)
	}
	if panda.PandaDirExists() {
		t.Error("wrote a configuration it could not complete")
	}
}

func TestQuickInitVaultRecordsAnAppRoleConfiguration(t *testing.T) {
	setupProviderTest(t)
	t.Setenv("PANDA_VAULT_URL", "https://vault.example:8200")
	t.Setenv("PANDA_VAULT_ROLE_ID", "role-1")
	t.Setenv("PANDA_VAULT_SECRET_ID", "secret-1")

	if err := runQuickInit("vault"); err != nil {
		t.Fatalf("runQuickInit(vault) error = %v", err)
	}

	creds := readCredentialsOrFail(t)
	if creds.Provider != "vault" {
		t.Errorf("provider = %q, want vault", creds.Provider)
	}
	if creds.VaultURL != "https://vault.example:8200" {
		t.Errorf("vaultUrl = %q", creds.VaultURL)
	}
	if creds.VaultAuthMethod != "approle" {
		t.Errorf("vaultAuthMethod = %q, want approle", creds.VaultAuthMethod)
	}
	if creds.VaultRoleId != "role-1" || creds.VaultSecretId != "secret-1" {
		t.Errorf("role/secret not recorded: %q / %q", creds.VaultRoleId, creds.VaultSecretId)
	}

	config, err := panda.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig() error = %v", err)
	}
	if config.Provider.Type != "vault" {
		t.Errorf("config provider = %q, want vault", config.Provider.Type)
	}
}

func TestQuickInitVaultInfersTokenAuthentication(t *testing.T) {
	setupProviderTest(t)
	t.Setenv("PANDA_VAULT_URL", "https://vault.example:8200")
	t.Setenv("PANDA_VAULT_TOKEN", "hvs.token")

	if err := runQuickInit("vault"); err != nil {
		t.Fatalf("runQuickInit(vault) error = %v", err)
	}

	creds := readCredentialsOrFail(t)
	if creds.VaultAuthMethod != "token" {
		t.Errorf("vaultAuthMethod = %q, want token", creds.VaultAuthMethod)
	}
	if creds.VaultToken != "hvs.token" {
		t.Errorf("vaultToken was not recorded")
	}
}

func TestQuickInitVaultRejectsAnUnknownAuthMethod(t *testing.T) {
	setupProviderTest(t)
	t.Setenv("PANDA_VAULT_URL", "https://vault.example:8200")
	t.Setenv("PANDA_VAULT_AUTH_METHOD", "kerberos")

	err := runQuickInit("vault")
	if err == nil {
		t.Fatal("an unknown auth method was accepted")
	}
	if !strings.Contains(err.Error(), "kerberos") {
		t.Errorf("refusal does not name the method: %v", err)
	}
}

func TestQuickInitInfisicalNamesEveryMissingVariable(t *testing.T) {
	setupProviderTest(t)

	err := runQuickInit("infisical")
	if err == nil {
		t.Fatal("runQuickInit succeeded with no Infisical environment")
	}
	for _, name := range infisicalRequiredEnv {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s not named in the refusal: %v", name, err)
		}
	}
	if panda.PandaDirExists() {
		t.Error("wrote a configuration it could not complete")
	}
}

func TestQuickInitInfisicalRecordsItsConfiguration(t *testing.T) {
	setupProviderTest(t)
	t.Setenv("PANDA_INFISICAL_CLIENT_ID", "cid")
	t.Setenv("PANDA_INFISICAL_CLIENT_SECRET", "csecret")
	t.Setenv("PANDA_INFISICAL_PROJECT_ID", "pid")

	if err := runQuickInit("infisical"); err != nil {
		t.Fatalf("runQuickInit(infisical) error = %v", err)
	}

	creds := readCredentialsOrFail(t)
	if creds.Provider != "infisical" {
		t.Errorf("provider = %q, want infisical", creds.Provider)
	}
	if creds.InfisicalProjectId != "pid" {
		t.Errorf("project id not recorded: %q", creds.InfisicalProjectId)
	}
	if creds.InfisicalEnvironment != "dev" {
		t.Errorf("environment = %q, want the safe default dev", creds.InfisicalEnvironment)
	}
}

func TestQuickInitNonLocalWritesNoLocalKey(t *testing.T) {
	setupProviderTest(t)
	t.Setenv("PANDA_VAULT_URL", "https://vault.example:8200")
	t.Setenv("PANDA_VAULT_TOKEN", "hvs.token")

	if err := runQuickInit("vault"); err != nil {
		t.Fatalf("runQuickInit(vault) error = %v", err)
	}

	env, err := os.ReadFile(".env")
	if err == nil && strings.Contains(string(env), "PANDA_KEY_") {
		t.Errorf("a key was generated \"for\" a secret manager: %s", env)
	}
}

func TestQuickInitWithNoProviderStillMeansLocal(t *testing.T) {
	setupProviderTest(t)

	if err := runQuickInit(""); err != nil {
		t.Fatalf("runQuickInit error = %v", err)
	}

	if creds := readCredentialsOrFail(t); creds.Provider != "local" {
		t.Errorf("provider = %q, want local", creds.Provider)
	}
	env, err := os.ReadFile(".env")
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if !strings.Contains(string(env), "PANDA_KEY_K1=") {
		t.Errorf(".env has no key: %s", env)
	}
}

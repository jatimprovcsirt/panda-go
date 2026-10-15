package cmd

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"

	"github.com/jatimprovcsirt/panda-go/crypto"
	"github.com/jatimprovcsirt/panda-go/telemetry"
)

var (
	force     bool
	token     string
	batchSize int
	delay     int
	pk        string
	dryRun    bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:     "panda",
	Short:   "PANDA CLI Tool for Go",
	Long:    `PANDA (Private And Secure Data Access) CLI tool for encryption key management and data migration.`,
	Version: "0.1.0",
}

// Execute adds all child commands to the root command and sets flags appropriately
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Add existing commands from main.go
	addRotateKeyCommand()
	addShredCommand()
	addMigrateCommand()
}

func addRotateKeyCommand() {
	var newKid string

	rotateCmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "Rotate encryption key",
		Run: func(cmd *cobra.Command, args []string) {
			if newKid == "" {
				fmt.Println("Error: --new-kid is required.")
				os.Exit(1)
			}
			reg := regexp.MustCompile(`[^A-Za-z0-9]`)
			normalizedKid := strings.ToUpper(reg.ReplaceAllString(newKid, "_"))
			envVarName := fmt.Sprintf("PANDA_KEY_%s", normalizedKid)

			// Generate the key, and report that one exists.
			keyBytes, err := telemetry.NewEncryptionKey()
			if err != nil {
				fmt.Printf("Error generating key: %v\n", err)
				os.Exit(1)
			}
			keyBase64 := base64.StdEncoding.EncodeToString(keyBytes)

			envPath := filepath.Join(".", ".env")
			examplePath := filepath.Join(".", ".env.example")

			appendEnv(envPath, envVarName, keyBase64)
			appendEnv(examplePath, envVarName, "")

			appendEnv(envPath, "PANDA_DEFAULT_KID", newKid)
			appendEnv(examplePath, "PANDA_DEFAULT_KID", "")

			fmt.Println("Key rotated successfully!")
			fmt.Printf("New active write KID: %s\n", newKid)
			fmt.Printf("New key written to .env: %s\n", envVarName)
		},
	}
	rotateCmd.Flags().StringVarP(&newKid, "new-kid", "n", "", "New Key Identifier")
	rootCmd.AddCommand(rotateCmd)
}

func addShredCommand() {
	shredCmd := &cobra.Command{
		Use:   "shred [kid]",
		Short: "Crypto-shred: permanently delete an encryption key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targetKid := args[0]
			if !force {
				fmt.Printf("Are you absolutely sure you want to shred key '%s'? ALL data encrypted with this key will be permanently lost! (y/n) ", targetKid)
				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println("Action cancelled.")
					return
				}
				input = strings.TrimSpace(strings.ToLower(input))
				if input != "y" && input != "yes" {
					fmt.Println("Action cancelled.")
					return
				}
			}

			reg := regexp.MustCompile(`[^A-Za-z0-9]`)
			normalizedKid := strings.ToUpper(reg.ReplaceAllString(targetKid, "_"))
			envVarName := fmt.Sprintf("PANDA_KEY_%s", normalizedKid)

			envPath := filepath.Join(".", ".env")
			examplePath := filepath.Join(".", ".env.example")

			shredded := false
			for _, filePath := range []string{envPath, examplePath} {
				if _, err := os.Stat(filePath); err == nil {
					contentBytes, err := os.ReadFile(filePath)
					if err != nil {
						continue
					}
					content := string(contentBytes)
					regexStr := fmt.Sprintf(`(?m)^%s=.*\r?\n?`, envVarName)
					r := regexp.MustCompile(regexStr)
					if r.MatchString(content) {
						content = r.ReplaceAllString(content, "")
						os.WriteFile(filePath, []byte(content), 0644)
						shredded = true
					}
				}
			}

			if shredded {
				fmt.Fprintf(os.Stderr, "🔥 Key '%s' has been permanently SHREDDED from configuration!\n", targetKid)
			} else {
				fmt.Printf("Key '%s' was not found in environment configuration.\n", targetKid)
			}
		},
	}
	shredCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")
	rootCmd.AddCommand(shredCmd)
}

func addMigrateCommand() {
	migrateCmd := &cobra.Command{
		Use:   "migrate [table] [column] [kid]",
		Short: "Migrate plaintext columns to encrypted envelopes",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			table := args[0]
			column := args[1]
			targetKid := args[2]

			connectionType := os.Getenv("DB_CONNECTION")
			if connectionType == "" {
				connectionType = "mysql"
			}
			host := os.Getenv("DB_HOST")
			if host == "" {
				host = "127.0.0.1"
			}
			port := os.Getenv("DB_PORT")
			if port == "" {
				if connectionType == "postgres" || connectionType == "pgsql" {
					port = "5432"
				} else {
					port = "3306"
				}
			}
			database := os.Getenv("DB_DATABASE")
			username := os.Getenv("DB_USERNAME")
			if username == "" {
				username = "root"
			}
			password := os.Getenv("DB_PASSWORD")

			if database == "" {
				fmt.Println("Error: DB_DATABASE environment variable is not configured.")
				os.Exit(1)
			}

			var dsn string
			var driver string
			if connectionType == "postgres" || connectionType == "pgsql" {
				driver = "postgres"
				dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, username, password, database)
			} else {
				driver = "mysql"
				dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", username, password, host, port, database)
			}

			db, err := sql.Open(driver, dsn)
			if err != nil {
				fmt.Printf("Connection failed: %v\n", err)
				os.Exit(1)
			}
			defer db.Close()

			if err := db.Ping(); err != nil {
				fmt.Printf("Ping failed: %v\n", err)
				os.Exit(1)
			}

			runMigration(db, driver, table, column, targetKid, pk, batchSize, delay, dryRun)
		},
	}
	migrateCmd.Flags().IntVarP(&batchSize, "batch-size", "b", 100, "Number of rows to process per chunk")
	migrateCmd.Flags().IntVarP(&delay, "delay", "d", 100, "Delay between chunks in milliseconds")
	migrateCmd.Flags().StringVarP(&pk, "pk", "p", "id", "Primary key column name")
	migrateCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Estimate migration scope without modifying data")
	rootCmd.AddCommand(migrateCmd)
}

func runMigration(db *sql.DB, driver, table, column, targetKid, pkColumn string, batchSize, delayMs int, isDryRun bool) {
	// Implementation from original main.go
	fmt.Printf("Migration target: %s.%s using KID: %s\n", table, column, targetKid)

	// Ensure checkpoint table
	var createTableSQL string
	if driver == "postgres" {
		createTableSQL = `
			CREATE TABLE IF NOT EXISTS panda_migration_state (
				id SERIAL PRIMARY KEY,
				table_name VARCHAR(128) NOT NULL,
				column_name VARCHAR(128) NOT NULL,
				last_processed_id VARCHAR(255) NOT NULL,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				CONSTRAINT unique_target UNIQUE (table_name, column_name)
			)`
	} else {
		createTableSQL = `
			CREATE TABLE IF NOT EXISTS panda_migration_state (
				id INT AUTO_INCREMENT PRIMARY KEY,
				table_name VARCHAR(128) NOT NULL,
				column_name VARCHAR(128) NOT NULL,
				last_processed_id VARCHAR(255) NOT NULL,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
				UNIQUE KEY unique_target (table_name, column_name)
			)`
	}

	if _, err := db.Exec(createTableSQL); err != nil {
		fmt.Printf("Failed to create checkpoint table: %v\n", err)
		os.Exit(1)
	}

	// Fetch checkpoint
	var checkpoint string
	var row *sql.Row
	if driver == "postgres" {
		row = db.QueryRow("SELECT last_processed_id FROM panda_migration_state WHERE table_name = $1 AND column_name = $2", table, column)
	} else {
		row = db.QueryRow("SELECT last_processed_id FROM panda_migration_state WHERE table_name = ? AND column_name = ?", table, column)
	}
	err := row.Scan(&checkpoint)
	if err == sql.ErrNoRows {
		checkpoint = ""
	} else if err != nil {
		fmt.Printf("Failed to scan checkpoint: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Last processed primary key ID: %s\n", checkpoint)

	if isDryRun {
		fmt.Println("[DRY RUN] Estimating scope...")
		var countSQL string
		var countRow *sql.Row
		if checkpoint != "" {
			if driver == "postgres" {
				countSQL = fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s > $1", table, pkColumn)
				countRow = db.QueryRow(countSQL, checkpoint)
			} else {
				countSQL = fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s > ?", table, pkColumn)
				countRow = db.QueryRow(countSQL, checkpoint)
			}
		} else {
			countSQL = fmt.Sprintf("SELECT COUNT(*) FROM %s", table)
			countRow = db.QueryRow(countSQL)
		}

		var remaining int
		if err := countRow.Scan(&remaining); err != nil {
			fmt.Printf("Error counting rows: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Total remaining rows to scan: %d\n", remaining)
		return
	}

	// Run migration
	keyProvider := crypto.NewLocalKeyProvider()
	cipher := crypto.NewFieldCipher(keyProvider, nil)

	lastID := checkpoint
	totalProcessed := 0
	totalEncrypted := 0

	for {
		var selectSQL string
		var rows *sql.Rows
		var err error

		if lastID != "" {
			if driver == "postgres" {
				selectSQL = fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s > $1 ORDER BY %s ASC LIMIT $2", pkColumn, column, table, pkColumn, pkColumn)
				rows, err = db.Query(selectSQL, lastID, batchSize)
			} else {
				selectSQL = fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s > ? ORDER BY %s ASC LIMIT ?", pkColumn, column, table, pkColumn, pkColumn)
				rows, err = db.Query(selectSQL, lastID, batchSize)
			}
		} else {
			if driver == "postgres" {
				selectSQL = fmt.Sprintf("SELECT %s, %s FROM %s ORDER BY %s ASC LIMIT $1", pkColumn, column, table, pkColumn)
				rows, err = db.Query(selectSQL, batchSize)
			} else {
				selectSQL = fmt.Sprintf("SELECT %s, %s FROM %s ORDER BY %s ASC LIMIT ?", pkColumn, column, table, pkColumn)
				rows, err = db.Query(selectSQL, batchSize)
			}
		}

		if err != nil {
			fmt.Printf("Query failed: %v\n", err)
			os.Exit(1)
		}

		var batchRows []struct {
			id  string
			val sql.NullString
		}

		for rows.Next() {
			var idVal interface{}
			var val sql.NullString
			if err := rows.Scan(&idVal, &val); err != nil {
				rows.Close()
				fmt.Printf("Scan failed: %v\n", err)
				os.Exit(1)
			}

			var idStr string
			switch v := idVal.(type) {
			case int64:
				idStr = strconv.FormatInt(v, 10)
			case []byte:
				idStr = string(v)
			case string:
				idStr = v
			default:
				idStr = fmt.Sprintf("%v", v)
			}

			batchRows = append(batchRows, struct {
				id  string
				val sql.NullString
			}{id: idStr, val: val})
		}
		rows.Close()

		if len(batchRows) == 0 {
			break
		}

		tx, err := db.Begin()
		if err != nil {
			fmt.Printf("Failed to begin transaction: %v\n", err)
			os.Exit(1)
		}

		currentBatchLastID := lastID
		for _, rowData := range batchRows {
			currentBatchLastID = rowData.id
			if !rowData.val.Valid || rowData.val.String == "" {
				continue
			}

			val := rowData.val.String
			isAlreadyEncrypted := strings.HasPrefix(val, "{") && strings.Contains(val, `"v":`)
			if isAlreadyEncrypted {
				continue
			}

			envelope, err := cipher.Encrypt([]byte(val), targetKid, "migration-cli", fmt.Sprintf("%s.%s", table, column))
			if err != nil {
				tx.Rollback()
				fmt.Printf("Encryption failed for row %s: %v\n", rowData.id, err)
				os.Exit(1)
			}

			envJSON, err := envelope.ToJSON()
			if err != nil {
				tx.Rollback()
				fmt.Printf("JSON generation failed for row %s: %v\n", rowData.id, err)
				os.Exit(1)
			}

			var updateSQL string
			if driver == "postgres" {
				updateSQL = fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s = $2", table, column, pkColumn)
				_, err = tx.Exec(updateSQL, envJSON, rowData.id)
			} else {
				updateSQL = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?", table, column, pkColumn)
				_, err = tx.Exec(updateSQL, envJSON, rowData.id)
			}

			if err != nil {
				tx.Rollback()
				fmt.Printf("Update failed for row %s: %v\n", rowData.id, err)
				os.Exit(1)
			}
			totalEncrypted++
		}

		lastID = currentBatchLastID
		var upsertSQL string
		if driver == "postgres" {
			upsertSQL = `
				INSERT INTO panda_migration_state (table_name, column_name, last_processed_id)
				VALUES ($1, $2, $3)
				ON CONFLICT (table_name, column_name)
				DO UPDATE SET last_processed_id = EXCLUDED.last_processed_id, updated_at = CURRENT_TIMESTAMP`
			_, err = tx.Exec(upsertSQL, table, column, lastID)
		} else {
			upsertSQL = `
				INSERT INTO panda_migration_state (table_name, column_name, last_processed_id)
				VALUES (?, ?, ?)
				ON DUPLICATE KEY UPDATE last_processed_id = ?`
			_, err = tx.Exec(upsertSQL, table, column, lastID, lastID)
		}

		if err != nil {
			tx.Rollback()
			fmt.Printf("Upsert checkpoint failed: %v\n", err)
			os.Exit(1)
		}

		if err := tx.Commit(); err != nil {
			fmt.Printf("Transaction commit failed: %v\n", err)
			os.Exit(1)
		}

		totalProcessed += len(batchRows)
		fmt.Printf("Processed %d rows... Encrypted: %d\n", totalProcessed, totalEncrypted)

		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}

	fmt.Printf("Migration finished! Total rows processed: %d, Encrypted: %d\n", totalProcessed, totalEncrypted)
}

// Helper function to append to .env files
func appendEnv(filePath, name, value string) {
	var content string
	if _, err := os.Stat(filePath); err == nil {
		bytes, err := os.ReadFile(filePath)
		if err == nil {
			content = string(bytes)
		}
	}

	regexStr := fmt.Sprintf(`(?m)^%s=.*\r?\n?`, name)
	r := regexp.MustCompile(regexStr)

	if r.MatchString(content) {
		content = r.ReplaceAllString(content, fmt.Sprintf("%s=%s\n", name, value))
	} else {
		content += fmt.Sprintf("\n%s=%s\n", name, value)
	}

	os.WriteFile(filePath, []byte(strings.TrimSpace(content)+"\n"), 0644)
}

# PANDA Go SDK

**PANDA (Private And Secure Data Access)** — AES-256-GCM field-level encryption SDK for Go services.

> Melindungi data pribadi warga (NIK, nama, nomor HP, alamat) dari kebocoran database, sesuai amanah UU PDP No. 27/2022.

## Requirements

- Go ≥ 1.20

## Installation

```bash
go get github.com/jatimprovcsirt/panda-go
```

Atau, untuk menggunakan CLI bawaan, build binary-nya terlebih dahulu:

```bash
go build -o panda ./cmd/panda
# Kemudian pindahkan ke PATH:
# Linux/macOS: sudo mv panda /usr/local/bin/
# Windows: letakkan panda.exe di folder yang ada di PATH Anda
```

---

## 1. PANDA Master Key Initialization (Langkah Pertama yang Wajib)

Sebelum menulis kode integrasi apapun, Anda harus menghasilkan kunci master lokal untuk aplikasi Anda. Ini adalah gerbang keamanan satu kali sebelum PANDA bisa beroperasi.

### Langkah 1: Dapatkan PANDA Access Token

Anda harus memiliki PANDA Access Token untuk menginisialisasi kunci master aplikasi Anda.

**Daftar aplikasi dan dapatkan token di:** https://csirt.jatimprov.go.id/panda

> [!NOTE]
> Setiap aplikasi memerlukan token unik. Token digunakan sebagai gerbang keamanan satu kali untuk inisialisasi kunci.

### Langkah 2: Jalankan Perintah Init

Jalankan perintah berikut di direktori root proyek Anda. Ganti `YOUR_TOKEN` dengan PANDA Access Token yang diperoleh dari portal (panjang: 48 atau 64 karakter hex):

```bash
panda init --token YOUR_TOKEN
```

Setelah menjalankan perintah ini, wizard akan:
1. Memvalidasi token Anda
2. Meminta Anda memasukkan Key Identifier (KID) untuk kunci pertama
3. Menghasilkan kunci 256-bit yang aman secara kriptografis secara **lokal**
4. Menambahkan kunci dalam format base64 ke file `.env` Anda (misal: `PANDA_KEY_OPD_DUKCAPIL_KEY_1=...`)

> [!NOTE]
> Untuk pengembangan lokal, Anda dapat menggunakan demo token bawaan:
> `panda_demo_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2`

### Langkah 2: Apa yang Terjadi?

Perintah `init` melakukan hal berikut:
1. Memvalidasi format token Anda.
2. Menghasilkan kunci 256-bit yang aman secara kriptografis secara **lokal** (token tidak pernah menerima kunci ini).
3. Secara otomatis menambahkan kunci dalam format base64 ke file `.env` Anda (misal: `PANDA_KEY_OPD_DUKCAPIL_KEY_1=...`).

### Langkah 3: Muat Environment Variables

Go tidak memuat `.env` secara otomatis. Gunakan library seperti [`godotenv`](https://github.com/joho/godotenv):

```bash
go get github.com/joho/godotenv
```

```go
import "github.com/joho/godotenv"

func main() {
    // Muat .env sebelum menggunakan PANDA
    _ = godotenv.Load()
    // ...
}
```

Atau, ekspor variabel environment secara manual setelah `init`:

```bash
# Linux/macOS
export PANDA_KEY_OPD_DUKCAPIL_KEY_1="<nilai dari .env>"

# Windows (CMD)
set PANDA_KEY_OPD_DUKCAPIL_KEY_1=<nilai dari .env>

# Windows (PowerShell)
$env:PANDA_KEY_OPD_DUKCAPIL_KEY_1="<nilai dari .env>"
```

### Langkah 4: Restart Aplikasi (Penting!)

> [!IMPORTANT]
> Setelah `init` menulis ke `.env`, Anda **HARUS merestart aplikasi/server** agar variabel environment baru terbaca. Ini berlaku untuk semua runtime: binary standalone, Docker container, systemd service, dsb.

### Menambahkan KID/Kunci Tambahan

Jika aplikasi Anda membutuhkan lebih dari satu kunci (misalnya untuk field data yang berbeda atau rotasi bertahap), gunakan perintah `generate` untuk menambahkan kunci tambahan tanpa memerlukan token:

```bash
# Kunci kedua: untuk field nomor HP
panda generate opd-dukcapil-key-2

# Kunci untuk blind index (suffix -idx wajib dipisah)
panda generate opd-dukcapil-key-1-idx
```

> [!NOTE]
> Perintah `generate` hanya dapat digunakan setelah inisialisasi awal dengan `init`. Tidak perlu token lagi untuk menambahkan kunci baru.

### Rotasi Kunci (Tanpa Portal)

Untuk merotasi kunci pada KID yang sudah ada, gunakan `rotate-key`. Perintah ini berjalan **sepenuhnya lokal** tanpa memerlukan token:

```bash
# Rotasi: buat kunci baru dan set sebagai default KID aktif
panda rotate-key --new-kid opd-dukcapil-key-2
```

### Menghapus Kunci (Crypto-Shred)

```bash
# Hapus kunci secara permanen (HATI-HATI: data yang dienkripsi dengan kunci ini tidak bisa didekripsi lagi!)
panda shred opd-dukcapil-key-old
```

---

## Infisical Setup (Production-Ready Alternative)

Untuk deployment produksi, disarankan menggunakan Infisical sebagai KeyProvider alih-alih LocalKeyProvider (env vars).

### Setup Infisical Cloud

1. **Buat Akun Infisical**
   - Daftar di https://infisical.com (free tier tersedia)
   - Buat project baru
   - Buat environment (dev, staging, prod)

2. **Buat Machine Identity**
   - Buka "Machine Identities" di project Anda
   - Klik "Create Machine Identity"
   - Pilih environment yang diakses
   - Copy Client ID dan Client Secret

3. **Upload Kunci Enkripsi**
   - Buka "Secrets" di project
   - Pilih environment
   - Klik "Add Secret"
   - Secret Key: `nik-key` (atau KID Anda)
   - Secret Value: `<base64-encoded-32-byte-key>` (generate dengan `openssl rand -base64 32`)

4. **Konfigurasi Aplikasi**
   ```bash
   # .env
   PANDA_KEY_PROVIDER_DRIVER=infisical
   PANDA_INFISICAL_SITE_URL=https://app.infisical.com
   PANDA_INFISICAL_CLIENT_ID=<client-id>
   PANDA_INFISICAL_CLIENT_SECRET=<client-secret>
   PANDA_INFISICAL_PROJECT_ID=<project-id>
   PANDA_INFISICAL_ENVIRONMENT=dev
   PANDA_INFISICAL_CACHE_TTL=300
   ```

### Menggunakan InfisicalKeyProvider dalam Kode

```go
package main

import (
    "github.com/jatimprovcsirt/panda-go/crypto"
)

func main() {
    // Baca dari environment variables atau config
    keyProvider := crypto.NewInfisicalKeyProvider(
        "https://app.infisical.com",
        "your-client-id",
        "your-client-secret",
        "your-project-id",
        "dev",
        300, // cache TTL in seconds
    )

    cipher := crypto.NewFieldCipher(keyProvider, nil, nil)

    // Sisa kode tetap sama
    envelope, err := cipher.Encrypt([]byte("3201012501990001"), "nik-key")
    // ...
}
```

**Keuntungan Infisical:**
- ✅ Production-ready dengan auto-renewal (tanpa token expiration)
- ✅ UI modern yang mudah digunakan
- ✅ Free tier untuk project kecil
- ✅ Cloud atau self-hosted options

Untuk setup lengkap Infisical, lihat [Infisical Setup Guide](../../docs/infisical-setup-guide.md).

---

## 2. Quick Start

### Langkah 1: Siapkan KeyProvider dan FieldCipher

```go
package main

import (
    "fmt"
    "github.com/jatimprovcsirt/panda-go/crypto"
)

func main() {
    // KeyProvider membaca PANDA_KEY_<KID> dari environment
    keyProvider := crypto.NewLocalKeyProvider()

    // FieldCipher menangani enkripsi, dekripsi, dan audit
    cipher := crypto.NewFieldCipher(keyProvider, nil, nil)
```

### Langkah 2: Enkripsi Data (Sebelum Disimpan ke DB)

```go
    rawNik := "3201012501990001"
    kid := "opd-dukcapil-key-1"

    env, err := cipher.Encrypt([]byte(rawNik), kid)
    if err != nil {
        panic(err)
    }

    jsonForDatabase, _ := env.ToJSON()
    // Simpan jsonForDatabase ke kolom TEXT di database
    fmt.Println(jsonForDatabase)
```

### Langkah 3: Dekripsi Data (Dari Query DB)

```go
    import "github.com/jatimprovcsirt/panda-go/crypto"

    // Ambil JSON dari database
    envelope, err := crypto.EnvelopeFromJSON(jsonFromDatabase)
    if err != nil { panic(err) }

    // A. Dekripsi dengan masking (aman untuk log/tampilan umum)
    masked, err := cipher.Decrypt(envelope)
    fmt.Println(string(masked)) // "32************01"

    // B. Dekripsi penuh — untuk audit/export
    raw, err := cipher.DecryptRaw(envelope)
    fmt.Println(string(raw)) // "3201012501990001"
}
```

### Langkah 4: Blind Index untuk Pencarian

Untuk mencari data terenkripsi, simpan hash deterministik (blind index) di kolom terpisah (`nik_bidx`):

```go
import "github.com/jatimprovcsirt/panda-go/blindindex"

// KID blind index HARUS menggunakan suffix -idx
blindIndexKid := "opd-dukcapil-key-1-idx"
blindIndexKey := keyProvider.GetKey(blindIndexKid)

// Saat INSERT/UPDATE: hitung blind index
blindIndexValue := blindindex.Generate([]byte(rawNik), blindIndexKey, "digits")
// Simpan blindIndexValue ke kolom 'nik_bidx'

// Saat SELECT: hash nilai pencarian dan query berdasarkan hash
searchHash := blindindex.Generate([]byte("3201012501990001"), blindIndexKey, "digits")
// db.Query("SELECT * FROM citizens WHERE nik_bidx = ?", searchHash)
```

---

## 3. Database Refactoring & Zero-Downtime Migration

Jika Anda memiliki aplikasi yang sudah berjalan dengan data plaintext di database, ikuti alur migrasi ini tanpa downtime.

### Alur Migrasi

```
Step 1: ALTER kolom → TEXT + tambah kolom _bidx
      ↓
Step 2: Init PANDA master key + restart server
      ↓
Step 3: Jalankan migrate CLI (konversi plaintext ke envelope)
      ↓
Step 4: Update kode aplikasi (enkripsi on-write, query via _bidx)
      ↓
Step 5: Backfill blind index untuk data yang sudah terenkripsi
```

### Step 1: Alter Kolom Database

```sql
ALTER TABLE citizens MODIFY COLUMN nik TEXT;
ALTER TABLE citizens ADD COLUMN nik_bidx VARCHAR(64) NULL;
CREATE INDEX idx_citizens_nik_bidx ON citizens(nik_bidx);
```

### Step 2: Init PANDA Key

Lihat Bagian 1 di atas.

### Step 3: Jalankan Migrasi CLI

```bash
# Konversi semua plaintext ke encrypted envelope (resumable jika terputus)
panda migrate citizens nik opd-dukcapil-key-1

# Opsi tambahan:
# --batch-size <n>  : jumlah baris per chunk (default: 100)
# --delay <ms>      : jeda antar chunk (default: 100ms)
# --pk <col>        : nama kolom primary key (default: id)
# --dry-run         : estimasi scope tanpa mengubah data
panda migrate citizens nik opd-dukcapil-key-1 --batch-size 500 --dry-run
```

Perintah ini menyimpan checkpoint di tabel `panda_migration_state`, jadi aman jika terputus dan bisa dilanjutkan.

### Step 4: Backfill Blind Index (Contoh Script Go)

```go
package main

import (
    "database/sql"
    "fmt"
    "github.com/jatimprovcsirt/panda-go/blindindex"
    "github.com/jatimprovcsirt/panda-go/crypto"
    _ "github.com/go-sql-driver/mysql"
)

func main() {
    keyProvider := crypto.NewLocalKeyProvider()
    cipher := crypto.NewFieldCipher(keyProvider, nil, nil)
    blindIndexKey := keyProvider.GetKey("opd-dukcapil-key-1-idx")

    db, _ := sql.Open("mysql", "user:pass@/dbname")
    defer db.Close()

    rows, _ := db.Query("SELECT id, nik FROM citizens WHERE nik_bidx IS NULL")
    defer rows.Close()

    for rows.Next() {
        var id int
        var nikJSON string
        rows.Scan(&id, &nikJSON)

        envelope, _ := crypto.EnvelopeFromJSON(nikJSON)
        rawVal, _ := cipher.DecryptRaw(envelope)

        hash := blindindex.Generate(rawVal, blindIndexKey, "digits")
        db.Exec("UPDATE citizens SET nik_bidx = ? WHERE id = ?", hash, id)
    }

    fmt.Println("Blind index backfill selesai!")
}
```

---

## 4. Referensi CLI

### Mode Non-Interaktif (Flags untuk CI/CD)

Semua perintah CLI dapat digunakan dalam mode non-interaktif dengan menggunakan flag. Ini sangat berguna untuk:

- **CI/CD pipelines** - Otomatisasi tanpa interaksi pengguna
- **Docker containers** - Inisialisasi otomatis saat container start
- **Infrastructure as Code** - Integrasi dengan Terraform, Ansible, dll
- **Automated testing** - Setup dan teardown otomatis

#### Perintah Init - Mode Non-Interaktif

```bash
# Quick init dengan Local provider (mode tercepat)
panda init --quick --token <token>

# Init tanpa generate kunci pertama (untuk automation lanjutan)
panda init --quick --token <token> --skip-key-gen

# Reinitialize paksa (overwrite konfigurasi yang sudah ada)
panda init --quick --token <token> --reinit
```

**Flag `init` yang tersedia:**

| Flag | Default | Deskripsi |
|------|---------|-----------|
| `--token <value>` | - | PANDA access token (atau set `PANDA_ACCESS_TOKEN` env) |
| `--quick` | `false` | Skip wizard, gunakan quick setup dengan local provider |
| `--reinit` | `false` | Reinitialize meskipun sudah pernah di-init sebelumnya |
| `--skip-key-gen` | `false` | Skip generate kunci pertama |

#### Perintah Generate - Mode Non-Interaktif

```bash
# Generate kunci dengan KID langsung (non-interactive)
panda generate my-new-key

# Generate dengan description
panda generate nik-key --description "Key for NIK encryption"

# Generate dengan flag --kid
panda generate --kid my-key
```

**Flag `generate` yang tersedia:**

| Flag | Default | Deskripsi |
|------|---------|-----------|
| `--kid <value>` | - | Key Identifier |
| `--description <text>` | - | Deskripsi untuk kunci |

#### Perintah Shred - Mode Non-Interaktif

```bash
# Hapus kunci dengan konfirmasi otomatis (hati-hati!)
panda shred old-deprecated-key --force
```

**Flag `shred` yang tersedia:**

| Flag | Short | Default | Deskripsi |
|------|-------|---------|-----------|
| `--force` | `-f` | `false` | Skip konfirmasi prompt (irreversible!) |

#### Perintah Migrate - Mode Non-Interaktif

```bash
# Migrasi batch processing dengan flags
panda migrate citizens nik default-key \
  --batch-size 500 \
  --delay 200 \
  --pk id \
  --dry-run

# Migrasi PostgreSQL dengan batch size custom
panda migrate users email email-key --batch-size 1000

# Migrasi dengan custom primary key
panda migrate transactions transaction_id txn-key --pk uuid
```

**Flag `migrate` yang tersedia:**

| Flag | Short | Default | Deskripsi |
|------|-------|---------|-----------|
| `--batch-size <n>` | `-b` | `100` | Jumlah baris per chunk |
| `--delay <ms>` | `-d` | `100` | Delay antar chunk (ms) |
| `--pk <col>` | `-p` | `id` | Nama kolom primary key |
| `--dry-run` | - | `false` | Estimasi scope tanpa mengubah data |

#### Perintah Rotate-Key - Mode Non-Interaktif

```bash
# Rotasi kunci ke KID baru
panda rotate-key --new-kid new-key-2024

# Rotasi kunci dengan KID custom
panda rotate-key --new-kid production-key-v2
```

**Flag `rotate-key` yang tersedia:**

| Flag | Short | Default | Deskripsi |
|------|-------|---------|-----------|
| `--new-kid <value>` | `-n` | - | **Wajib** - Key Identifier baru untuk rotasi |

#### Tabel Lengkap Referensi CLI

| Perintah | Memerlukan Token | Mode Non-Interaktif | Deskripsi |
|---|---|---:|---|
| `panda init --token <token>` | ✅ Ya | ✅ `--quick` | Inisialisasi PANDA (wizard atau quick mode) |
| `panda generate <kid>` | ❌ Tidak | ✅ (default non-interactive) | Generate kunci tambahan |
| `panda status` | ❌ Tidak | ✅ (default non-interactive) | Tampilkan status konfigurasi |
| `panda config` | ❌ Tidak | ✅ (default non-interactive) | Tampilkan detail konfigurasi lengkap |
| `panda deinit` | ❌ Tidak | ✅ (default non-interactive) | Hapus konfigurasi PANDA |
| `panda rotate-key --new-kid <kid>` | ❌ Tidak | ✅ (default non-interactive) | Rotasi kunci ke KID baru |
| `panda shred <kid>` | ❌ Tidak | ✅ `--force` | Hapus kunci permanen |
| `panda migrate <table> <col> <kid>` | ❌ Tidak | ✅ (default non-interactive) | Migrasi plaintext → encrypted |

---

## 5. Build CLI dari Source

```bash
go build -o panda ./cmd/panda

# Linux/macOS — pasang ke PATH
sudo mv panda /usr/local/bin/

# Verifikasi
panda --help
```

---

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

Apache License 2.0 — see `LICENSE` for the full text and `NOTICE` for
attribution.

Previously MIT. Apache-2.0 is equally permissive and adds an express patent
grant and a trademark clause, which MIT is silent on — it matters here because
this is cryptographic software that other agencies and vendors are expected to
embed in their own systems.

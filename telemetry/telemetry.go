package telemetry

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/jatimprovcsirt/panda-go/internal/panda"
)

const (
	DemoToken = "panda_demo_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2"

	// The flush trigger, pinned in panda-spec/telemetry-format.md: whichever
	// of these is reached first. Time alone reports too rarely on a busy
	// installation; volume alone, too rarely on a quiet one.
	defaultFlushInterval = 300 * time.Second
	defaultFlushVolume   = 1000

	// Hard timeout. Every telemetry call is fail-silent, and a call that
	// could hang is not fail-silent.
	httpTimeout = 2 * time.Second
)

// SDKVersion is reported to the portal and identifies which release an
// installation runs, so the portal can warn it about a known-vulnerable one.
//
// The cipher used to pass a literal "0.1.0" here, which would have made that
// warning wrong for every installation.
//
// It is read from the build rather than declared, because a constant here
// would be a second definition of a number that already exists in the git tag
// and the changelog — free to drift from them, which is what happened to the
// version strings in panda-py and panda-node, in the shipped packages, for
// several releases.
var SDKVersion = detectVersion()

func detectVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	const module = "github.com/jatimprovcsirt/panda-go"

	// Built from inside this module: `go build ./cmd/panda`, or a
	// `go install` of the module itself.
	if info.Main.Path == module && isRelease(info.Main.Version) {
		return strings.TrimPrefix(info.Main.Version, "v")
	}

	// Built as a dependency of something else — the ordinary case for an
	// application that imports this SDK.
	for _, dep := range info.Deps {
		if dep.Path == module && isRelease(dep.Version) {
			return strings.TrimPrefix(dep.Version, "v")
		}
	}

	return "unknown"
}

// isRelease filters out the pseudo-versions a source build reports.
func isRelease(v string) bool {
	return v != "" && v != "(devel)"
}

// Kind is a counted operation. Exactly three are counted, and they are
// counted at the public cipher method rather than wherever someone remembered
// to add a call — which is how `decrypt`, the masked read and the most common
// path of all, came to be uncounted entirely.
type Kind int

const (
	Encrypt Kind = iota
	Decrypt
	DecryptRaw
)

// Recorder accumulates operation counts and reports them.
//
// Go runs one process per installation in the ordinary case, so the counters
// live in memory and nothing else is needed. The multi-worker store the spec
// describes is for runtimes that recycle worker processes — PHP-FPM, gunicorn.
type Recorder struct {
	mu     sync.Mutex
	client *http.Client
	once   sync.Once

	counters Counters
	// windowStart is when the first unreported operation happened, so
	// windowSeconds describes the counts actually being sent.
	windowStart   time.Time
	flushing      bool
	noTokenLogged bool
}

var defaultRecorder = NewRecorder()

// NewRecorder creates a recorder. Callers who want their own — a test, or an
// application embedding the SDK — can have one; everything else uses the
// package-level recorder through Count and Flush.
func NewRecorder() *Recorder {
	return &Recorder{client: &http.Client{Timeout: httpTimeout}}
}

// Count records one operation. Cheap: a mutex and three additions, no I/O.
//
// This is what the cipher calls. It used to call an HTTP client directly,
// once per encrypt and once per decryptRaw, which made a library whose whole
// promise is that it works without the portal issue a network request inside
// its hot path.
func Count(k Kind) { defaultRecorder.Increment(k) }

// Flush reports the counters now, if the trigger has fired and there is
// something to report.
func Flush() { defaultRecorder.Flush() }

// Increment records one operation and reports it if the trigger has fired.
func (r *Recorder) Increment(k Kind) {
	if telemetryDisabled() {
		return
	}

	r.mu.Lock()
	if r.counters.total() == 0 {
		r.windowStart = time.Now()
	}
	switch k {
	case Encrypt:
		r.counters.Encrypts++
	case Decrypt:
		r.counters.Decrypts++
	case DecryptRaw:
		r.counters.DecryptsRaw++
	}
	due := r.dueLocked()
	r.mu.Unlock()

	if due {
		// Not awaited, so an operation never waits on the network.
		go r.Flush()
	}
}

func (r *Recorder) dueLocked() bool {
	if r.counters.total() == 0 {
		return false
	}
	if r.counters.total() >= defaultFlushVolume {
		return true
	}
	return time.Since(r.windowStart) >= defaultFlushInterval
}

// Flush sends the accumulated counts.
//
// Fail-silent: a DNS failure, a timeout, a refused connection or any non-2xx
// response leaves the counters untouched so the next attempt carries them.
// That is the half of the delta rule that keeps a portal outage from quietly
// discarding the operations that happened during it.
func (r *Recorder) Flush() {
	if telemetryDisabled() {
		return
	}

	r.mu.Lock()
	if r.flushing || r.counters.total() == 0 {
		r.mu.Unlock()
		return
	}
	r.flushing = true
	sent := r.counters
	window := int(time.Since(r.windowStart).Seconds())
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.flushing = false
		r.mu.Unlock()
	}()

	creds, err := panda.ReadCredentials()
	if err != nil || creds == nil || creds.Token == "" {
		r.logNoToken()
		return
	}

	body, err := BuildUsagePayload(UsageInput{
		Token:         creds.Token,
		SDKVersion:    SDKVersion,
		WindowSeconds: window,
		Counters:      sent,
	})
	if err != nil {
		return
	}

	resp, err := r.client.Post(TelemetryURL, "application/json", bytes.NewBufferString(body))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return
	}

	// Only now, and only what was sent. Subtracting rather than zeroing keeps
	// operations that happened while the request was in flight — resetting
	// would discard them, and nothing would report it.
	r.mu.Lock()
	r.counters.subtract(sent)
	if r.counters.total() == 0 {
		r.windowStart = time.Time{}
	}
	r.mu.Unlock()
}

// NewEncryptionKey generates a 32-byte key and reports that one exists.
//
// The one definition of "a key was generated", so the event cannot be
// forgotten at one of the call sites — which is how `decrypt`, the most common
// read path of all, came to be uncounted. Every key-producing path goes
// through here: init, `panda generate` and `rotate-key`.
func NewEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("telemetry: generate key: %w", err)
	}

	ReportKey(key)

	return key, nil
}

// ReportKey reports a newly generated key, once. It carries the fingerprint,
// which the usage event must not.
func ReportKey(key []byte) {
	if telemetryDisabled() {
		return
	}

	creds, err := panda.ReadCredentials()
	if err != nil || creds == nil || creds.Token == "" {
		return
	}

	body, err := BuildKeyPayload(creds.Token, SDKVersion, key)
	if err != nil {
		return
	}

	resp, err := (&http.Client{Timeout: httpTimeout}).
		Post(TelemetryURL, "application/json", bytes.NewBufferString(body))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// logNoToken says once that nothing can be reported, rather than never saying
// it and leaving the portal's figures quietly wrong.
func (r *Recorder) logNoToken() {
	r.once.Do(func() {
		log.Println("panda: telemetry has no access token to report under; run 'panda init'. Counts are kept until then.")
	})
}

func telemetryDisabled() bool {
	v := os.Getenv("PANDA_TELEMETRY_DISABLED")
	return v == "1" || v == "true"
}

func (c *Counters) total() uint64 { return c.Encrypts + c.Decrypts + c.DecryptsRaw }

func (c *Counters) subtract(o Counters) {
	c.Encrypts -= o.Encrypts
	c.Decrypts -= o.Decrypts
	c.DecryptsRaw -= o.DecryptsRaw
}

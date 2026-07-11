package audit

import (
	"context"
	"log/slog"
	"os"
	"time"
)

type AuditLogger struct {
	logger *slog.Logger
}

func NewAuditLogger(logger *slog.Logger) *AuditLogger {
	if logger == nil {
		// Default structured JSON logger outputting to stderr/stdout
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return &AuditLogger{
		logger: logger,
	}
}

func (l *AuditLogger) Log(
	actor string,
	field string,
	kid string,
	eventType string,
	outcome string,
	extra ...interface{},
) {
	attrs := []slog.Attr{
		slog.String("timestamp", time.Now().Format(time.RFC3339)),
		slog.String("actor", actor),
		slog.String("field", field),
		slog.String("kid", kid),
		slog.String("eventType", eventType), // decrypt_masked | decrypt_raw | encrypt | rotate | shred
		slog.String("outcome", outcome),     // success | auth_failure | malformed_envelope | key_not_found
	}

	// Add any extra arguments as log context attributes
	l.logger.LogAttrs(context.Background(), slog.LevelInfo, "PANDA Audit Event", attrs...)
}

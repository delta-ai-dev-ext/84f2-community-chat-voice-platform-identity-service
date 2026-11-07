// Package migrations embeds the versioned SQL migrations shipped with the
// service so the binary can migrate the schema at startup.
package migrations

import "embed"

// FS holds every *.sql migration file.
//
//go:embed *.sql
var FS embed.FS

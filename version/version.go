// Package version provides build-time version information for go-mitmproxy.
// These values are set via ldflags during the build process.
package version

var (
	// Version is the semantic version of the build.
	// Set via ldflags: -X github.com/denisvmedia/go-mitmproxy/version.Version=x.y.z.
	Version = "dev"

	// Commit is the git commit hash of the build.
	// Set via ldflags: -X github.com/denisvmedia/go-mitmproxy/version.Commit=abc123.
	Commit = "unknown"

	// Date is the build date in RFC3339 format.
	// Set via ldflags: -X github.com/denisvmedia/go-mitmproxy/version.Date=2024-01-01T00:00:00Z.
	Date = "unknown"
)

// String returns a formatted version string including version, commit, and date.
func String() string {
	return Version + " (" + Commit + ", built " + Date + ")"
}

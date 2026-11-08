package store

import (
	"errors"
	"path/filepath"
	"strings"
)

// ObjectNamespace identifies the configured storage boundary, without credentials. Recovery must
// not attach two independent databases to overlapping files: either worker could delete the other's
// data. Provider aliases outside these configurations still require operator review.
type ObjectNamespace struct {
	Backend  string `json:"backend"`
	Root     string `json:"root,omitempty"`
	Bucket   string `json:"bucket,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
}

func Namespace(b Backend) (ObjectNamespace, error) {
	info := b.Describe()
	text := func(k string) string { s, _ := info[k].(string); return s }
	n := ObjectNamespace{Backend: text("backend")}
	switch n.Backend {
	case "local":
		root, err := filepath.Abs(text("root"))
		if err != nil || text("root") == "" {
			return n, errors.New("local storage namespace is unavailable")
		}
		root, err = filepath.EvalSymlinks(root)
		if err != nil {
			return n, err
		}
		n.Root = filepath.Clean(root)
	case "gcs":
		n.Bucket, n.Prefix = text("bucket"), text("prefix")
		if n.Bucket == "" {
			return n, errors.New("bucket namespace is unavailable")
		}
	case "s3":
		n.Bucket, n.Prefix, n.Endpoint = text("bucket"), text("prefix"), text("endpoint")
		if n.Bucket == "" || n.Endpoint == "" {
			return n, errors.New("S3 namespace is unavailable")
		}
	default:
		return n, errors.New("backend has no stable recovery namespace")
	}
	return n, nil
}
func (a ObjectNamespace) Overlaps(b ObjectNamespace) bool {
	if a.Backend != b.Backend {
		return false
	}
	if a.Backend == "local" {
		if a.Root == "" || b.Root == "" {
			return true
		}
		nested := func(root, path string) bool {
			rel, err := filepath.Rel(root, path)
			return err == nil && (rel == "." || filepath.IsLocal(rel))
		}
		return nested(a.Root, b.Root) || nested(b.Root, a.Root)
	}
	if a.Bucket != b.Bucket || a.Endpoint != b.Endpoint {
		return false
	}
	return strings.HasPrefix(a.Prefix, b.Prefix) || strings.HasPrefix(b.Prefix, a.Prefix)
}

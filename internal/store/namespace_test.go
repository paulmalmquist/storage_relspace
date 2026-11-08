package store

import "testing"

func TestRecoveryNamespaceOverlap(t *testing.T) {
	cases := []struct {
		a, b ObjectNamespace
		want bool
	}{
		{ObjectNamespace{Backend: "gcs", Bucket: "b", Prefix: "objects/"}, ObjectNamespace{Backend: "gcs", Bucket: "b", Prefix: "objects/copy/"}, true},
		{ObjectNamespace{Backend: "gcs", Bucket: "b", Prefix: "source/"}, ObjectNamespace{Backend: "gcs", Bucket: "b", Prefix: "recovery/"}, false},
		{ObjectNamespace{Backend: "gcs", Bucket: "b", Prefix: "objects/"}, ObjectNamespace{Backend: "gcs", Bucket: "c", Prefix: "objects/"}, false},
		{ObjectNamespace{Backend: "local", Root: "/data/blobs"}, ObjectNamespace{Backend: "local", Root: "/data/blobs/copy"}, true},
		{ObjectNamespace{Backend: "local", Root: "/data/blobs"}, ObjectNamespace{Backend: "local", Root: "/data/recovery"}, false},
	}
	for _, c := range cases {
		if c.a.Overlaps(c.b) != c.want || c.b.Overlaps(c.a) != c.want {
			t.Errorf("overlap %v %v wanted %v", c.a, c.b, c.want)
		}
	}
}

package backup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// decodeRow rejects duplicate columns instead of silently accepting the last value.
func decodeRow(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("row must be a JSON object")
	}
	row := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid column name")
		}
		if _, exists := row[key]; exists {
			return nil, fmt.Errorf("duplicate column %q", key)
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		row[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after row")
	}
	return row, nil
}

func stringColumn(row map[string]json.RawMessage, key string) string {
	var out string
	_ = json.Unmarshal(row[key], &out)
	return out
}

func appObjectPrefix(app, id string) string {
	return "apps/" + strings.ReplaceAll(app, ":", "/") + "/" + id + "/"
}

func rowScope(table, app string, raw []byte) error {
	row, err := decodeRow(raw)
	if err != nil {
		return err
	}
	if table == "principals" {
		return nil
	} // intentionally shared; merged without overwriting
	if stringColumn(row, "app") != app {
		return fmt.Errorf("row belongs to another app")
	}
	switch table {
	case "blobs", "blob_parts":
		key := stringColumn(row, "storage_key")
		id := stringColumn(row, "id")
		if table == "blob_parts" {
			id = stringColumn(row, "blob_id")
		}
		var version int
		_ = json.Unmarshal(row["aad_version"], &version)
		// Old assigned blobs retain their opaque pre-app object keys. They may not
		// name any app's prefix. Current objects must live under this exact blob.
		legacy := table == "blobs" && version == 2
		if _, err := objectPath(".", key); err != nil {
			return err
		}
		if id == "" || !store.ValidStorageKey(key) || len(key) < 2 ||
			(!legacy && !strings.HasPrefix(key, appObjectPrefix(app, id))) ||
			(legacy && strings.HasPrefix(key, "apps/")) {
			return fmt.Errorf("object key is outside its app and blob scope")
		}
	case "audit_heads", "audit_events":
		if !strings.HasPrefix(stringColumn(row, "chain"), "app:"+app+":") {
			return fmt.Errorf("audit chain is outside its app scope")
		}
	}
	return nil
}

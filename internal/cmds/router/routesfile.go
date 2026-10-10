package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// RoutesFile is the typed route data the front door reads at runtime, as the
// mounted file carries it. It holds the same values the flags do and goes
// through the same refusals: no field is an nginx directive.
type RoutesFile struct {
	Backend Backend `json:"backend"`
	Routes  []Route `json:"routes"`
}

// ParseRoutesFile decodes typed route data as the front door reads it: an
// unknown field is refused, so a key this image does not know cannot pass for
// route data. The chart writes that document, and its test parses the rendered
// one here.
func ParseRoutesFile(content []byte) (RoutesFile, error) {
	var file RoutesFile
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return RoutesFile{}, err
	}
	return file, nil
}

// readRoutesFile returns cfg with the file's backend and routes in place of
// the flags', validated as a whole. A file the renderer would refuse is
// returned as an error, so the caller keeps the configuration it is serving.
func readRoutesFile(cfg Config, path string) (Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	file, err := ParseRoutesFile(content)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Backend = file.Backend
	cfg.Routes = file.Routes
	validated, err := cfg.Validate()
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return validated, nil
}

package format

import (
	"errors"
	"strings"
)

var ErrBadPath = errors.New("invalid path")

// CleanPath validates a repository-relative path. It rejects traversal, empty
// segments and control characters, and returns the path without a leading
// slash. A trailing slash (directory) is preserved.
func CleanPath(p string) (string, error) {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", nil
	}
	dir := strings.HasSuffix(p, "/")
	trimmed := strings.TrimSuffix(p, "/")
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", ErrBadPath
		}
		for _, c := range seg {
			if c < 0x20 || c == 0x7f || c == '\\' {
				return "", ErrBadPath
			}
		}
	}
	if len(p) > 1024 {
		return "", ErrBadPath
	}
	if dir {
		return trimmed + "/", nil
	}
	return trimmed, nil
}

package keyscan

import (
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// GetPathsByGlob takes a slice of strings that should be expanded via globbing, and returns
//  the expansions.
// Note that globbing may only recognise errors in the glob pattern, not IO problems.
// See the documentation for the filepath module for more info.
//  --> https://golang.org/pkg/path/filepath/#Glob
// Note that we're also absoluting and 'cleaning' them, because relative paths are kind of useless in output.
func GetPathsByGlob(g []string) ([]string, error) {
	log.WithFields(log.Fields{"num_globs": len(g)}).Info("Expanding globs")
	paths := make([]string, 0)
	for _, v := range g {
		log.WithFields(log.Fields{"glob": v}).Debug("Expanding glob")
		matches, err := filepath.Glob(v)
		log.WithFields(log.Fields{"matches": len(matches)}).Debug("Expanded")
		if err != nil {
			log.Error(err)
		}
		for _, m := range matches {
			log.WithFields(log.Fields{"path": m}).Debug("Getting canonical path for match")
			m = filepath.Clean(m)
			if !filepath.IsAbs(m) {
				m, err = filepath.Abs(m)
				if err != nil {
					log.Error(err)
				}
			}
			paths = append(paths, m)
		}
	}
	log.WithFields(log.Fields{"num_matches": len(paths)}).Info("Expansion complete")
	return paths, nil
}

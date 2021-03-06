package keyscan

import (
	log "github.com/sirupsen/logrus"
)

// Go runs the whole scan based on params.
func (ctx *ScanContext) Go() {
	ctx.GatherKeysToScanFromGlobs(ctx.Params.TargetGlobs)
	ctx.GatherForbiddenKeysFromFiles(ctx.Params.PermittedKeyFiles)
	ctx.GatherPermittedKeysFromFiles(ctx.Params.ForbiddenKeyFiles)
	ctx.ScanKeysForProblems()
	ctx.PrintProblemReport()
}

// ScanParams contains all the lists of things we need to check for while scanning for duplicate public keys.
type ScanParams struct {
	TargetGlobs       []string // List of files to parse and scan keys from.
	PermittedKeyFiles []string // List of files containing keys that are explicitly allowed to be owned by multiple users.
	ForbiddenKeyFiles []string // List of files containing keys that cannot be used by any user.
	IgnoredOwners     []string // Users whose keys are ignored in scans.
	LowerUIDBound     int      // Ignore system users, with UIDs below this. (e.g. root, nobody, cups)
	// IgnoredGroups []string // TODO Later?
}

// ScanContext is a container for all the data about a scan for keys.
type ScanContext struct {
	Params        ScanParams    // Configuration options.
	FoundKeys     []OwnedPubKey // All the keys that have been found from files and will be checked.
	PermittedKeys []OwnedPubKey // Keys that are explicitly allowed to be owned by multiple users.
	ForbiddenKeys []OwnedPubKey // Keys that are cannot be used by any user.
	Problems      ProblemSet    // Any problems found during the scan.
}

type PKProblemType uint

const (
	NoProblem PKProblemType = iota //
	KeyForbidden
	DuplicateKey
	// KeyTypeDeprecated // TODO Later?
)

// GetProblemTypeText gets a textual description from numeric problem class ID.
func GetProblemTypeText(pt PKProblemType) string {
	problemTypeTexts := []string{"No Problem", "Forbidden Key", "Duplicate Key"}
	return problemTypeTexts[uint(pt)]
}

// ProblemSet is contained by ScanContext to classify the problems we find.
type ProblemSet struct {
	ForbiddenKeys []PubKeyProblem
	DuplicateKeys []PubKeyProblem
}

// PubKeyProblem contains one problem found during a scan, along with the keys that were problematic.
type PubKeyProblem struct {
	ProblemType PKProblemType
	ProblemKey  OwnedPubKey
	RelatedKeys []OwnedPubKey
}

func appendEachKey(a []OwnedPubKey, b []OwnedPubKey) []OwnedPubKey {
	for _, k := range b {
		a = append(a, k)
	}
	return a
}

func (ctx *ScanContext) GatherKeysToScanFromGlobs(globs []string) {
	filenames, err := GetPathsByGlob(ctx.Params.TargetGlobs)
	if err != nil {
		log.Error(err)
	}
	ctx.GatherKeysToScanFromFiles(filenames)
}

func (ctx *ScanContext) GatherKeysToScanFromFiles(filenames []string) {
	opks := GatherKeysFromFiles(filenames)
	ctx.FoundKeys = appendEachKey(ctx.FoundKeys, opks)
}

func (ctx *ScanContext) GatherForbiddenKeysFromFiles(filenames []string) {
	opks := GatherKeysFromFiles(filenames)
	ctx.ForbiddenKeys = appendEachKey(ctx.ForbiddenKeys, opks)
}

func (ctx *ScanContext) GatherPermittedKeysFromFiles(filenames []string) {
	opks := GatherKeysFromFiles(filenames)
	ctx.PermittedKeys = appendEachKey(ctx.PermittedKeys, opks)
}

// GatherKeysFromFiles takes a slice of filenames and returns all the public keys it finds in them with metadata attached.
func GatherKeysFromFiles(filenames []string) []OwnedPubKey {
	opks := make([]OwnedPubKey, 0)
	for _, name := range filenames {
		numKeys := 0
		log.WithFields(log.Fields{"file": name}).Debug("Getting keys from new file")
		keys, err := GetOwnedPubKeysFromFile(name)
		if err != nil {
			log.Error(err)
		}
		numKeys += len(keys)
		for _, key := range keys {
			log.WithFields(log.Fields{"owner": key.Owner, "source": key.SourceFile}).Debug("Adding found key")
			opks = append(opks, key)
		}
		log.WithFields(log.Fields{"new_keys": numKeys, "file": name}).Debug("Key gathering from file complete")
	}
	return opks
}

// ScanKeysForProblems scans all a context's found keys for problems, and return true if any were found, false otherwise.
func (ctx *ScanContext) ScanKeysForProblems() bool {
	log.Debug("Context starting scan for problems")
	anyProblems := false
	for _, v := range ctx.FoundKeys {
		log.WithFields(log.Fields{"owner": v.Owner, "source": v.SourceFile}).Debug("Checking key")
		isProblem, keyProblem := ctx.IsKeyAProblem(v)
		if isProblem {
			anyProblems = true
			log.WithFields(log.Fields{"class": keyProblem.ProblemType}).Debug("Problem detected")
			if keyProblem.ProblemType == KeyForbidden {
				ctx.Problems.ForbiddenKeys = append(ctx.Problems.ForbiddenKeys, keyProblem)
			}
			if keyProblem.ProblemType == DuplicateKey {
				ctx.Problems.DuplicateKeys = append(ctx.Problems.DuplicateKeys, keyProblem)
			}
		}
	}
	log.WithFields(log.Fields{"duplicate_keys": len(ctx.Problems.DuplicateKeys), "forbidden_keys": len(ctx.Problems.ForbiddenKeys)}).Info("Problem scan complete")
	return anyProblems
}

func (ctx *ScanContext) IsKeyAProblem(k OwnedPubKey) (bool, PubKeyProblem) {
	if ctx.IsKeyPermitted(k) {
		return false, PubKeyProblem{}
	}
	if ctx.ShouldIgnoreOwner(k.Owner) {
		return false, PubKeyProblem{}
	}
	if ctx.IsKeyForbidden(k) {
		forbidding := ctx.FindKeysForbidding(k)
		p := PubKeyProblem{ProblemType: KeyForbidden, ProblemKey: k, RelatedKeys: forbidding}
		return true, p
	}
	if dups := ctx.GetDuplicatesOf(k); len(dups) != 0 {
		p := PubKeyProblem{ProblemType: DuplicateKey, ProblemKey: k, RelatedKeys: append(dups, k)}
		return true, p
	}
	return false, PubKeyProblem{}
}

// IsKeyPermitted returns whether the public key in k is one allowed to be anywhere.
func (ctx *ScanContext) IsKeyPermitted(k OwnedPubKey) bool {
	return IsKeyInSlice(k, ctx.PermittedKeys)
}

// IsKeyForbidden returns whether the public key in k is one forbidden from use by anyone.
func (ctx *ScanContext) IsKeyForbidden(k OwnedPubKey) bool {
	return IsKeyInSlice(k, ctx.ForbiddenKeys)
}

// FindKeysForbidding returns the actual entries in forbiddenkeys that will cause a key to be marked as forbidden.
// There's almost certainly some further abstraction that would remove redundancy around this file but I'm real tired.
func (ctx *ScanContext) FindKeysForbidding(k OwnedPubKey) []OwnedPubKey {
	results := make([]OwnedPubKey, 0)
	for _, opk := range ctx.ForbiddenKeys {
		if k.HasSameKeyAs(opk) {
			results = append(results, opk)
		}
	}
	return results
}

// GetDuplicatesOf finds and returns duplicates of an OwnedPubKey k in the ScanContext's FoundKeys.
func (ctx *ScanContext) GetDuplicatesOf(k OwnedPubKey) []OwnedPubKey {
	results := make([]OwnedPubKey, 0)
	for _, opk := range ctx.FoundKeys {
		if k.HasSameKeyAs(opk) {
			// Skip any opk that comes from the same source.
			if k.SourceFile != opk.SourceFile {
				results = append(results, opk)
			}
		}
	}
	return results
}

// ShouldIgnoreOwner returns true if the ScanContext's Params are set to ignore the user passed.
func (ctx *ScanContext) ShouldIgnoreOwner(s string) bool {
	return ctx.Params.ShouldIgnoreOwner(s)
}

// ShouldIgnoreOwner returns true if the ScanParams are set to ignore the user passed.
func (sp *ScanParams) ShouldIgnoreOwner(s string) bool {
	if stringInStringSlice(s, sp.IgnoredOwners) {
		return true
	}
	if UIDForUserIsBelow(sp.LowerUIDBound, s) {
		return true
	}
	return false
}

func UIDForUserIsBelow(lb int, username string) bool {
	uid, err := getUIDForUser(username)
	if err != nil {
		log.Error(err)
		return false // There's not much we can do in the case of error, so... return false? HACK
	}
	if uid < lb {
		return true
	}
	return false
}

// Returns true if the exact string is an element in the string slice.
func stringInStringSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

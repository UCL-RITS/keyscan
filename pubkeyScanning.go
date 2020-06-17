package main

import (
	log "github.com/sirupsen/logrus"
)

// Gets complete list of user home directories, scans all authorized_keys and authorized_keys2 files for duplicates,
//  ignoring all keys in a permitted list, treating all keys in the forbidden list as if they were duplicated,
//  and ignoring all files owned by users or groups in the ignore lists.
//func ScanAllAuthorizedKeys(s *ScanParams) {

//}

// ScanParams contains all the lists of things we need to check for while scanning for duplicate public keys.
type ScanParams struct {
	TargetFiles   []string      // List of files to parse and scan keys from.
	PermittedKeys []OwnedPubKey // Keys that are explicitly allowed to be owned by multiple users.
	ForbiddenKeys []OwnedPubKey // Keys that are cannot be used by any user.
	IgnoredOwners []string      // Users whose keys are ignored in scans.
	LowerUIDBound int           // Ignore system users, with UIDs below this. (e.g. root, nobody, cups)
	// IgnoredGroups []string // TODO Later?
}

// ScanContext is a container for all the data about a scan for keys.
type ScanContext struct {
	Params    ScanParams      // Configuration options.
	FoundKeys []OwnedPubKey   // All the keys that have been found from files and will be checked.
	Problems  []PubKeyProblem // Any problems found during the scan.
}

type PKProblemType uint

const (
	NoProblem PKProblemType = iota //
	KeyForbidden
	DuplicateKey
	// KeyTypeDeprecated // TODO Later?
)

func GetProblemTypeText(pt PKProblemType) string {
	problemTypeTexts := []string{"No Problem", "Forbidden Key", "Duplicate Key"}
	return problemTypeTexts[uint(pt)]
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

func (ctx *ScanContext) GatherKeysToScanFromFiles(filenames []string) {
	opks := GatherKeysFromFiles(filenames)
	ctx.FoundKeys = appendEachKey(ctx.FoundKeys, opks)
}

func (ctx *ScanContext) GatherForbiddenKeysFromFiles(filenames []string) {
	opks := GatherKeysFromFiles(filenames)
	ctx.Params.ForbiddenKeys = appendEachKey(ctx.Params.ForbiddenKeys, opks)
}

func (ctx *ScanContext) GatherPermittedKeysFromFiles(filenames []string) {
	opks := GatherKeysFromFiles(filenames)
	ctx.Params.PermittedKeys = appendEachKey(ctx.Params.PermittedKeys, opks)
}

// GatherKeysFromFiles takes a slice of filenames and returns all the public keys it finds in them with metadata attached.
func GatherKeysFromFiles(filenames []string) []OwnedPubKey {
	opks := make([]OwnedPubKey, 0)
	for _, name := range filenames {
		numKeys := 0
		log.WithFields(log.Fields{"file": name}).Debug("Getting keys from new file")
		keys, err := GetOwnedPubKeysFromFile(name)
		if err != nil {
			// TODO: proper error handling
			panic(err)
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
			ctx.Problems = append(ctx.Problems, keyProblem)
		}
	}
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
		p := PubKeyProblem{ProblemType: KeyForbidden, ProblemKey: k}
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
	return IsKeyInSlice(k, ctx.Params.PermittedKeys)
}

// IsKeyForbidden returns whether the public key in k is one forbidden from use by anyone.
func (ctx *ScanContext) IsKeyForbidden(k OwnedPubKey) bool {
	return IsKeyInSlice(k, ctx.Params.ForbiddenKeys)
}

// GetDuplicatesOf finds and returns duplicates of an OwnedPubKey k in the ScanContext's FoundKeys.
func (ctx *ScanContext) GetDuplicatesOf(k OwnedPubKey) []OwnedPubKey {
	results := make([]OwnedPubKey, 0)
	for _, opk := range ctx.FoundKeys {
		if k.HasSameKeyAs(opk) {
			// Skip an opk that has the *exact* same contents: i.e. either the original k, or a copy of the same key from the same source file.
			if !k.HasAllSameDataAs(opk) {
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
		// TODO: handle properly... somehow
		panic(err)
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

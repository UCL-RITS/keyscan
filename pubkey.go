package main

import (
	"bytes"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

// An OwnedPubKey contains a single ssh public key along with provenance information.
type OwnedPubKey struct {
	Owner      string        // The username of the owner of the file the key came from (text)
	OwnerID    int           // The uid of that user
	Key        ssh.PublicKey // The underlying key struct, contains key bytes, comments, options
	SourceFile string        // The file the key came from
	SourceLine int           // The line in that file the key came from
	Comment    string        // The comment on that key in the source file
}

// GetOwnedPubKeysFromFile attempts to get all the keys from an authorized_keys file and return them
//  as a slice of OwnedPubKeys, labelled with the file's owner and the filename they came from.
func GetOwnedPubKeysFromFile(filename string) ([]OwnedPubKey, error) {
	owner, uid, err := getFileOwnerNameAndID(filename)
	if err != nil {
		return []OwnedPubKey{}, err
	}

	fileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return []OwnedPubKey{}, err
	}

	keys, lineNums, comments, err := ParseKeysFromBytes(fileBytes)
	if err != nil {
		return []OwnedPubKey{}, err
	}
	ownedKeys := make([]OwnedPubKey, 0)
	for i, v := range keys {
		ownedKeys = append(ownedKeys, OwnedPubKey{Owner: owner, OwnerID: uid, SourceFile: filename, Key: v, SourceLine: lineNums[i], Comment: comments[i]})
	}
	return ownedKeys, nil
}

// This is a wrapper around ParseAuthorizedKey to let it read more than one from a byteslice (i.e. file contents).
func ParseKeysFromBytes(in []byte) ([]ssh.PublicKey, []int, []string, error) {
	keys := make([]ssh.PublicKey, 0)
	lineNums := make([]int, 0)
	comments := make([]string, 0)

	// remainder is carried over between loop iterations below and used to track progress through a file('s bytes).
	var remainder []byte
	remainder = in

	for len(remainder) != 0 {
		// This is the prototype for ParseAuthorizedKey:
		// func ParseAuthorizedKey(in []byte) (out PublicKey, comment string, options []string, rest []byte, err error)
		var newKey ssh.PublicKey
		var err error
		var comment string
		newKey, comment, _, remainder, err = ssh.ParseAuthorizedKey(remainder)
		if err != nil {
			return nil, nil, nil, err
		}
		keys = append(keys, newKey)
		lineNums = append(lineNums, getKeyLine(in, remainder))
		comments = append(comments, comment)
	}
	return keys, lineNums, comments, nil
}

// The key parser takes chunks off the input and leaves the rest in `remainder`.
// This function returns what line of the input `in` the parser has gotten to, so
//  we can label the keys with what line of a file they came from.
func getKeyLine(in []byte, remainder []byte) int {
	lenIn := len(in)
	lenRe := len(remainder)
	// diff should be all the segments cut off by the key parser so far.
	diff := in[:lenIn-lenRe]
	numNewLines := bytes.Count(diff, []byte("\n"))
	return numNewLines
}

// GetDuplicateKeysFromSlice takes an OwnedPubKey and a slice of OwnedPubKeys and
//  returns a slice of the OPKs from the slice that have the same key.
func GetDuplicateKeysFromSlice(k OwnedPubKey, ks []OwnedPubKey) []OwnedPubKey {
	dupes := make([]OwnedPubKey, 0)
	for _, v := range ks {
		if k.HasSameKeyAs(v) {
			dupes = append(dupes, v)
		}
	}
	return dupes
}

// IsKeyInSlice takes an OwnedPubKey k and a slice of OwnedPubKeys and
//  returns true if k's key occurs in in the slice.
// (It's very similar to GetDuplicateKeysFromSlice but short-circuits.)
func IsKeyInSlice(k OwnedPubKey, ks []OwnedPubKey) bool {
	for _, v := range ks {
		if k.HasSameKeyAs(v) {
			return true
		}
	}
	return false
}

// HasSameKeyAs compares the public key for an OwnedPubKey struct using IsKeyInOwnedPubKeyEqual in an OO-y way.
// Returns true if the two keys are the same.
func (a OwnedPubKey) HasSameKeyAs(b OwnedPubKey) bool {
	return IsKeyInOwnedPubKeyEqual(a, b)
}

// IsKeyInOwnedPubKeyEqual compares two OwnedPubKeys and returns true if the public keys they contain are the same.
func IsKeyInOwnedPubKeyEqual(a OwnedPubKey, b OwnedPubKey) bool {
	return IsKeyEqual(a.Key, b.Key)
}

// IsKeyEqual converts two public keys into the wire format and compares them, returning true if they are the same key.
func IsKeyEqual(a ssh.PublicKey, b ssh.PublicKey) bool {
	keyA := a.Marshal()
	keyB := b.Marshal()
	return IsByteSliceEqual(keyA, keyB)
}

// IsOPKEqual compares all fields of an OwnedPubKey to determine whether they're the same.
func IsOPKEqual(a OwnedPubKey, b OwnedPubKey) bool {
	if a.Owner != b.Owner {
		return false
	}
	if a.SourceFile != b.SourceFile {
		return false
	}
	if !IsKeyInOwnedPubKeyEqual(a, b) {
		return false
	}
	return true
}

// HasAllSameData is the same as IsOPKEqual but called via a call on the struct rather than objectively.
func (a OwnedPubKey) HasAllSameDataAs(b OwnedPubKey) bool {
	return IsOPKEqual(a, b)
}

// IsByteSliceEqual compares two slices of bytes and returns true if they contain the same bytes, false otherwise.
func IsByteSliceEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	l := len(a)
	for i := 0; i < l; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

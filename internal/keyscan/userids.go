package keyscan

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Takes a username, returns the user's numeric ID. Doesn't work under Windows, because Windows doesn't do numeric Uids I think.
func getUIDForUser(username string) (int, error) {
	user, err := user.Lookup(username)
	if err != nil {
		return -1, err
	}

	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return -1, err
	}

	return uid, nil
}

// Takes a filename and returns the owner's username as a string.
func getFileOwnerName(filename string) (string, error) {
	username, _, err := getFileOwnerNameAndID(filename)
	if err != nil {
		return "", err
	}
	return username, err
}

// Takes a filename and returns the owner's username *and* numeric ID.
func getFileOwnerNameAndID(filename string) (string, int, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return "", -1, err
	}

	var UID int
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		UID = int(stat.Uid)
	} else {
		// This function doesn't work if the backing store doesn't support the syscalls used.
		return "", -1, errors.New("this OS does not support syscalls providing file ownership information")
	}

	ownerUser, err := user.LookupId(strconv.FormatInt(int64(UID), 10))
	if err != nil {
		return "", -1, err
	}
	return ownerUser.Username, UID, nil
}

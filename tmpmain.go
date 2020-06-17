package main

import (
	"fmt"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

func main() {
	b, err := ioutil.ReadFile("authorized_keys")
	if err != nil {
		fmt.Println(err)
	}
	keys := ParseKeysFromBytes(b)
	fmt.Printf("%v\n", keys)
	fmt.Printf("%d keys found.\n", len(keys))

	ownedKeys, err := GetOwnedPubKeysFromFile("authorized_keys")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%v\n", ownedKeys)

	log.SetLevel(log.DebugLevel)

	c := &ScanContext{}
	c.GatherForbiddenKeysFromFiles([]string{"forbidden_keys"})
	c.GatherPermittedKeysFromFiles([]string{"permitted_keys"})
	c.GatherKeysToScanFromFiles([]string{"authorized_keys", "smauthorized_keys"})
	fmt.Println(c.FoundKeys)
	c.ScanKeysForProblems()
	fmt.Println(c.Problems)
	c.PrintProblemReport()
}

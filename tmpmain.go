package main

import (
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)

	c := &ScanContext{}
	c.GatherForbiddenKeysFromFiles([]string{"test-files/forbidden_keys"})
	c.GatherPermittedKeysFromFiles([]string{"test-files/permitted_keys"})
	c.GatherKeysToScanFromFiles([]string{"test-files/keytypes_test", "test-files/authorized_keys_1", "test-files/authorized_keys_2"})
	c.ScanKeysForProblems()
	c.PrintProblemReport()
}

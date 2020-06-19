package main

import (
	"fmt"
	//log "github.com/sirupsen/logrus"
	"encoding/json"
)

func (ctx *ScanContext) PrintProblemReport() {
	problemsJsonBytes, err := json.Marshal(ctx.Problems)
	problemsJsonString := string(problemsJsonBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println(problemsJsonString)
}

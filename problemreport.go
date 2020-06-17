package main

import (
	"fmt"
	//log "github.com/sirupsen/logrus"
)

func (ctx *ScanContext) PrintProblemReport() {
	for _, problem := range ctx.Problems {
		BasicProblemOutput(problem)
	}
}

// Because I wasn't sure what to do with them, this is a really basic outputter.
func BasicProblemOutput(p PubKeyProblem) {
	fmt.Printf("Problem in %s: %s\n", p.ProblemKey.SourceFile, GetProblemTypeText(p.ProblemType))
}

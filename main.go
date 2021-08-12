package main

import (
	"os"

	"github.com/chenzhiwei/certctl/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// SPDX-License-Identifier: Apache-2.0

// Command schemalint checks schema files or directories against the
// repository schema rules. Exit status is 1 if any finding is reported.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tantranshsangathan/sanchalan/internal/schemalint"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: schemalint <file-or-dir>...")
		os.Exit(2)
	}
	failed := false
	for _, arg := range os.Args[1:] {
		err := filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".schema.json") {
				return nil
			}
			findings, err := schemalint.File(p)
			if err != nil {
				return err
			}
			for _, f := range findings {
				fmt.Println(f)
				failed = true
			}
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if failed {
		os.Exit(1)
	}
}

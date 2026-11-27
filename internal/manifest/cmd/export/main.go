// Command export writes the path-free executable contract for offline tooling.
package main

import (
	"aurasplit/internal/manifest"
	"os"
)

func main() {
	if _, err := os.Stdout.Write(manifest.JSON()); err != nil {
		os.Exit(1)
	}
}

//go:build windows

package main

import (
	"io"
	"strings"
	"testing"
)

// The test binary is itself a running image, so openSelfImage must succeed
// and pin it: renaming the file while the handle is open must fail.
func TestOpenSelfImage(t *testing.T) {
	f, err := openSelfImage()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(f, head); err != nil || string(head) != "MZ" {
		t.Fatalf("not a PE image: %q %v", head, err)
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Fatal("handle must be read-only")
	}
}

func TestScrubDetail(t *testing.T) {
	in := "open C:\\Users\\Some Name\\AppData\\x.conf: denied\r\nnext"
	got := scrubDetail(in)
	if strings.Contains(got, "Some Name") || strings.ContainsAny(got, "\r\n") || !strings.Contains(got, `\Users\<user>\AppData`) {
		t.Fatalf("scrubDetail = %q", got)
	}
	if len(scrubDetail(strings.Repeat("a", 2000))) > maxStateDetail+4 {
		t.Fatal("detail not truncated")
	}
}

func TestTakeFlag(t *testing.T) {
	args, found := takeFlag([]string{"run", "--DEBUG"}, debugFlag)
	if !found || len(args) != 1 || args[0] != "run" {
		t.Fatalf("takeFlag = %v %v", args, found)
	}
	if _, found := takeFlag([]string{"run"}, debugFlag); found {
		t.Fatal("flag found without being present")
	}
}

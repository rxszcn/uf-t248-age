// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18

package armor_test

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"strings"
	"testing"

	agetest "c2sp.org/CCTV/age"
	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/internal/format"
)

func ExampleNewWriter() {
	publicKey := "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm"
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		log.Fatalf("Failed to parse public key %q: %v", publicKey, err)
	}

	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)

	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		log.Fatalf("Failed to create encrypted file: %v", err)
	}
	if _, err := io.WriteString(w, "Black lives matter."); err != nil {
		log.Fatalf("Failed to write to encrypted file: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close encrypted file: %v", err)
	}

	if err := armorWriter.Close(); err != nil {
		log.Fatalf("Failed to close armor: %v", err)
	}

	fmt.Printf("%s[...]", buf.Bytes()[:35])
	// Output:
	// -----BEGIN AGE ENCRYPTED FILE-----
	// [...]
}

var privateKey = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"

func ExampleNewReader() {
	fileContents := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4YWdhZHZ0WG1PZldDT1hD
K3RPRzFkUlJnWlFBQlUwemtjeXFRMFp6V1VFCnRzZFV3a3Vkd1dSUWw2eEtrRkVv
SHcvZnp6Q3lqLy9HMkM4ZjUyUGdDZjQKLS0tIDlpVUpuVUQ5YUJyUENFZ0lNSTB2
ekUvS3E5WjVUN0F5ZWR1ejhpeU5rZUUKsvPGYt7vf0o1kyJ1eVFMz1e4JnYYk1y1
kB/RRusYjn+KVJ+KTioxj0THtzZPXcjFKuQ1
-----END AGE ENCRYPTED FILE-----`

	// DO NOT hardcode the private key. Store it in a secret storage solution,
	// on disk if the local machine is trusted, or have the user provide it.
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key %q: %v", privateKey, err)
	}

	out := &bytes.Buffer{}
	f := strings.NewReader(fileContents)
	armorReader := armor.NewReader(f)

	r, err := age.Decrypt(armorReader, identity)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Failed to read encrypted file: %v", err)
	}

	fmt.Printf("File contents: %q\n", out.Bytes())
	// Output:
	// File contents: "Black lives matter."
}

func TestArmor(t *testing.T) {
	t.Run("PartialLine", func(t *testing.T) { testArmor(t, 611) })
	t.Run("FullLine", func(t *testing.T) { testArmor(t, 10*format.BytesPerLine) })
}

func TestWriterLifecycle(t *testing.T) {
	t.Run("CloseWithoutWrite", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := armor.NewWriter(buf)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if want := armor.Header + "\n" + armor.Footer + "\n"; buf.String() != want {
			t.Errorf("output = %q, want %q", buf.String(), want)
		}
	})
	t.Run("WriteAfterClose", func(t *testing.T) {
		w := armor.NewWriter(io.Discard)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if n, err := w.Write([]byte("x")); n != 0 || err == nil {
			t.Errorf("Write after Close = %d, %v", n, err)
		}
	})
}

func testArmor(t *testing.T, size int) {
	buf := &bytes.Buffer{}
	w := armor.NewWriter(buf)
	plain := make([]byte, size)
	rand.Read(plain)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		t.Fatal("PEM decoding failed")
	}
	if len(block.Headers) != 0 {
		t.Error("unexpected headers")
	}
	if block.Type != "AGE ENCRYPTED FILE" {
		t.Errorf("unexpected type %q", block.Type)
	}
	if !bytes.Equal(block.Bytes, plain) {
		t.Error("PEM decoded value doesn't match")
	}
	if !bytes.Equal(buf.Bytes(), pem.EncodeToMemory(block)) {
		t.Error("PEM re-encoded value doesn't match")
	}

	r := armor.NewReader(buf)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Error("decoded value doesn't match")
	}
}

func FuzzMalleability(f *testing.F) {
	tests, err := fs.ReadDir(agetest.Vectors, ".")
	if err != nil {
		f.Fatal(err)
	}
	seeds := 0
	for _, test := range tests {
		contents, err := fs.ReadFile(agetest.Vectors, test.Name())
		if err != nil {
			f.Fatal(err)
		}
		header, contents, ok := bytes.Cut(contents, []byte("\n\n"))
		if !ok {
			f.Fatal("testkit file without header")
		}
		if bytes.Contains(header, []byte("armored: yes")) {
			f.Add(contents)
			seeds++
		}
	}
	if seeds == 0 {
		f.Fatal("no armored test vectors")
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := armor.NewReader(bytes.NewReader(data))
		content, err := io.ReadAll(r)
		if err != nil {
			if _, ok := err.(*armor.Error); !ok {
				t.Errorf("error type is %T: %v", err, err)
			}
			t.Skip()
		}
		buf := &bytes.Buffer{}
		w := armor.NewWriter(buf)
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(normalize(buf.Bytes()), normalize(data)) {
			t.Error("re-encoded output different from input")
		}
	})
}

func normalize(f []byte) []byte {
	f = bytes.TrimSpace(f)
	f = bytes.Replace(f, []byte("\r\n"), []byte("\n"), -1)
	return f
}

// validArmoredFile is a self-contained, well-formed armored file used as the
// base for the header tolerance regression tests.
const validArmoredFile = `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4YWdhZHZ0WG1PZldDT1hD
K3RPRzFkUlJnWlFBQlUwemtjeXFRMFp6V1VFCnRzZFV3a3Vkd1dSUWw2eEtrRkVv
SHcvZnp6Q3lqLy9HMkM4ZjUyUGdDZjQKLS0tIDlpVUpuVUQ5YUJyUENFZ0lNSTB2
ekUvS3E5WjVUN0F5ZWR1ejhpeU5rZUUKsvPGYt7vf0o1kyJ1eVFMz1e4JnYYk1y1
kB/RRusYjn+KVJ+KTioxj0THtzZPXcjFKuQ1
-----END AGE ENCRYPTED FILE-----
`

// indentHeader returns file with spaces prepended to the header line only.
func indentHeader(file string, n int) string {
	return strings.Repeat(" ", n) + file
}

// TestHeaderTolerance covers the three required regression shapes — indented
// header line, trailing whitespace on the header line, and leading blank lines
// — plus CRLF variants. Everything LooksArmored accepts must decrypt, and the
// decoded payload must match the strict base file.
func TestHeaderTolerance(t *testing.T) {
	withTrailingWS := strings.Replace(validArmoredFile, "-----\n", "-----   \n", 1)
	withIndentAndTrailing := " \t " + strings.Replace(validArmoredFile, "-----\n", "----- \t\n", 1)
	crlf := strings.ReplaceAll(validArmoredFile, "\n", "\r\n")

	accepted := map[string]string{
		"plain header":               validArmoredFile,
		"indented header":            indentHeader(validArmoredFile, 3),
		"tab indented header":        "\t" + validArmoredFile,
		"trailing whitespace header": withTrailingWS,
		"indent and trailing header": withIndentAndTrailing,
		"leading blank lines":        "\n\n   \n" + validArmoredFile,
		"blank line before indented": "\n  \n   " + validArmoredFile,
		"CRLF header":                crlf,
		"indented CRLF header":       "   " + crlf,
		"indented CRLF trailing":     "   " + strings.ReplaceAll(withTrailingWS, "\n", "\r\n"),
	}

	want, err := io.ReadAll(armor.NewReader(strings.NewReader(validArmoredFile)))
	if err != nil {
		t.Fatal(err)
	}
	for name, variant := range accepted {
		t.Run(name, func(t *testing.T) {
			data := []byte(variant)
			if !armor.LooksArmored(data) {
				t.Fatalf("LooksArmored = false, want true")
			}
			got, err := io.ReadAll(armor.NewReader(bytes.NewReader(data)))
			if err != nil {
				t.Fatalf("NewReader rejected input that LooksArmored accepted: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Error("decoded payload differs from the strict base file")
			}
		})
	}
}

// TestHeaderStrictness pins the vectors that must not be relaxed: interior
// whitespace in the marker, trailing garbage on the header line, a wrong
// marker, and an empty line in the data area.
//
// Header-level defects must make LooksArmored return false; a body-level
// defect (empty data line) still has a valid header, so LooksArmored reports
// true while NewReader rejects it with an *armor.Error — proving the data area
// contract is untouched. In every case NewReader fails with *armor.Error.
func TestHeaderStrictness(t *testing.T) {
	// Insert a blank line between two data lines: the data area contract.
	withEmptyDataLine := strings.Replace(validArmoredFile,
		"K3RPRzFkUlJnWlFBQlUwemtjeXFRMFp6V1VFCnRzZFV3a3Vkd1dSUWw2eEtrRkVv\n",
		"K3RPRzFkUlJnWlFBQlUwemtjeXFRMFp6V1VFCnRzZFV3a3Vkd1dSUWw2eEtrRkVv\n\n", 1)

	tests := []struct {
		name         string
		variant      string
		wantDetected bool
		wantErr      string
	}{
		{"interior space in marker", strings.Replace(validArmoredFile,
			"BEGIN AGE", "BEGIN  AGE", 1), false, "invalid first line"},
		{"garbage after header", strings.Replace(validArmoredFile,
			"-----\n", "----- junk\n", 1), false, "invalid first line"},
		{"wrong marker", strings.Replace(validArmoredFile,
			armor.Header, "-----BEGIN SOMETHING ELSE-----", 1), false, "invalid first line"},
		{"empty line in data area", withEmptyDataLine, true, "empty line in armored data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.variant)
			if got := armor.LooksArmored(data); got != tt.wantDetected {
				t.Errorf("LooksArmored = %v, want %v", got, tt.wantDetected)
			}
			_, err := io.ReadAll(armor.NewReader(bytes.NewReader(data)))
			if err == nil {
				t.Fatalf("reader unexpectedly accepted %s", tt.name)
			}
			var armorErr *armor.Error
			if !errors.As(err, &armorErr) {
				t.Fatalf("error type is %T, want *armor.Error: %v", err, err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestHeaderWhitespaceBudget makes header indentation share the leading
// whitespace budget: just under the limit decodes, over the limit is rejected
// with an *armor.Error.
func TestHeaderWhitespaceBudget(t *testing.T) {
	const budget = 1024
	fits := strings.Repeat(" ", budget-1) + validArmoredFile
	overflows := strings.Repeat(" ", budget+1) + validArmoredFile

	if !armor.LooksArmored([]byte(fits)) {
		t.Error("LooksArmored rejected a header within the whitespace budget")
	}
	if _, err := io.ReadAll(armor.NewReader(strings.NewReader(fits))); err != nil {
		t.Errorf("reader rejected a header within budget: %v", err)
	}

	if _, err := io.ReadAll(armor.NewReader(strings.NewReader(overflows))); err == nil {
		t.Error("reader accepted a header exceeding the whitespace budget")
	} else {
		var armorErr *armor.Error
		if !errors.As(err, &armorErr) {
			t.Errorf("error type is %T, want *armor.Error: %v", err, err)
		}
	}
}

// TestLooksArmoredRejectsGarbage checks the probe itself, independent of the
// reader, for inputs that the old prefix match misclassified.
func TestLooksArmoredRejectsGarbage(t *testing.T) {
	notArmored := [][]byte{
		nil,
		[]byte(""),
		[]byte("\n\n  \n"),
		[]byte("age-encryption.org/v1\n"),
		[]byte("-----BEGIN AGE ENCRYPTED FILE----- junk\n"),
		[]byte("-----BEGIN  AGE ENCRYPTED FILE-----\n"),
		[]byte(" -----BEGIN OTHER-----\n"),
	}
	for i, data := range notArmored {
		if armor.LooksArmored(data) {
			t.Errorf("case %d: LooksArmored = true, want false for %q", i, data)
		}
	}
}

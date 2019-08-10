package shamir

import (
	"bytes"
	"testing"
)

func TestSplit_invalid(t *testing.T) {
	secret := []byte("test")

	if _, err := Split(secret, 0, 0); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 2, 3); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 1000, 3); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 10, 1); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 350, 300); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(nil, 3, 2); err == nil {
		t.Fatalf("expect error")
	}
}

func TestSplit(t *testing.T) {
	secret := []byte("test")

	out, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if len(out) != 5 {
		t.Fatalf("bad: %v", out)
	}

	for _, share := range out {
		if len(share) != len(secret)+1 {
			t.Fatalf("bad: %v", out)
		}
	}
}

func TestCombine_invalid(t *testing.T) {
	// Not enough parts
	if _, err := Combine(nil); err == nil {
		t.Fatalf("should err")
	}

	// Mis-match in length
	parts := [][]byte{
		[]byte("foo"),
		[]byte("ba"),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}

	//Too short
	parts = [][]byte{
		[]byte("f"),
		[]byte("b"),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}

	parts = [][]byte{
		[]byte("foo"),
		[]byte("foo"),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}
}

func TestCombine(t *testing.T) {
	secret := []byte("test")

	out, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// There is 5*4*3 possible choices,
	// we will just brute force try them all
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if j == i {
				continue
			}
			for k := 0; k < 5; k++ {
				if k == i || k == j {
					continue
				}
				parts := [][]byte{out[i], out[j], out[k]}
				recomb, err := Combine(parts)
				if err != nil {
					t.Fatalf("err: %v", err)
				}

				if !bytes.Equal(recomb, secret) {
					t.Errorf("parts: (i:%d, j:%d, k:%d) %v", i, j, k, parts)
					t.Fatalf("bad: %v %v", recomb, secret)
				}
			}
		}
	}
}

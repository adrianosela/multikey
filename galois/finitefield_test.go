package galois

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdd(t *testing.T) {
	if out := Add(16, 16); out != 0 {
		t.Fatalf("Bad: %v 16", out)
	}

	if out := Add(3, 4); out != 7 {
		t.Fatalf("Bad: %v 7", out)
	}
}

func TestMult(t *testing.T) {
	if out := Mult(3, 7); out != 9 {
		t.Fatalf("Bad: %v 9", out)
	}

	if out := Mult(3, 0); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}

	if out := Mult(0, 3); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}
}

func TestDivide(t *testing.T) {
	if out := Div(0, 7); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}

	if out := Div(3, 3); out != 1 {
		t.Fatalf("Bad: %v 1", out)
	}

	if out := Div(6, 3); out != 2 {
		t.Fatalf("Bad: %v 2", out)
	}

	if out := Div(6, 3); out != 2 {
		t.Fatalf("Bad: %v 2", out)
	}

	assert.Panics(t, func() { Div(6, 0) }, "Bad: not panicked")
}

func TestTables(t *testing.T) {
	for i := 1; i < 256; i++ {
		logV := logTable[i]
		expV := expTable[logV]
		if expV != uint8(i) {
			t.Fatalf("bad: %d log: %d exp: %d", i, logV, expV)
		}
	}
}

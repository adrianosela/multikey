package galois

import "testing"

func TestMakePolynomial(t *testing.T) {
	p := MakePolynomial(42, 2)
	if p.coefficients[0] != 42 {
		t.Fatalf("bad: %v", p.coefficients)
	}
}

func TestEvaluate(t *testing.T) {
	p := MakePolynomial(42, 1)
	if out := p.Evaluate(0); out != 42 {
		t.Fatalf("bad: %v", out)
	}

	out := p.Evaluate(1)
	exp := Add(42, Mult(1, p.coefficients[1]))
	if out != exp {
		t.Fatalf("bad: %v %v %v", out, exp, p.coefficients)
	}
}

func TestInterpolatePolynomial(t *testing.T) {
	for i := 0; i < 256; i++ {
		p := MakePolynomial(uint8(i), 2)

		xVals := []uint8{1, 2, 3}
		yVals := []uint8{p.Evaluate(1), p.Evaluate(2), p.Evaluate(3)}
		out := InterpolatePolynomial(xVals, yVals, 0)
		if out != uint8(i) {
			t.Fatalf("Bad: %v %d", out, i)
		}
	}
}

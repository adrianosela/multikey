package galois

import (
	"crypto/rand"
)

// Polynomial represents a polynomial of arbitrary degree
type Polynomial struct {
	coefficients []uint8
}

// MakePolynomial constructs a random polynomial of the given
// degree but with the provided intercept value.
func MakePolynomial(intercept, degree uint8) Polynomial {
	p := Polynomial{
		coefficients: make([]byte, degree+1),
	}

	// set the intercept
	p.coefficients[0] = intercept

	// assign random co-efficients to the polynomial
	rand.Read(p.coefficients[1:])

	return p
}

// Evaluate returns the value of the polynomial for the given x
func (p *Polynomial) Evaluate(x uint8) uint8 {
	// Special case the origin
	if x == 0 {
		return p.coefficients[0]
	}

	// Compute the polynomial value using Horner's method.
	degree := len(p.coefficients) - 1
	out := p.coefficients[degree]
	for i := degree - 1; i >= 0; i-- {
		coeff := p.coefficients[i]
		out = Add(Mult(out, x), coeff)
	}
	return out
}

// InterpolatePolynomial takes N sample points and returns
// the value at a given x using a lagrange interpolation.
func InterpolatePolynomial(xSamples, ySamples []uint8, x uint8) uint8 {
	limit := len(xSamples)
	var result, basis uint8
	for i := 0; i < limit; i++ {
		basis = 1
		for j := 0; j < limit; j++ {
			if i == j {
				continue
			}
			num := Add(x, xSamples[j])
			denom := Add(xSamples[i], xSamples[j])
			term := Div(num, denom)
			basis = Mult(basis, term)
		}
		group := Mult(ySamples[i], basis)
		result = Add(result, group)
	}
	return result
}

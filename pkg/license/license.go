// Package license checks SBOM package licenses against allow and deny lists.
//
// Licenses are SPDX ids, SPDX expressions, or free-text names. An expression
// such as "MIT OR GPL-3.0-only" passes when one side passes, and
// "MIT AND GPL-3.0-only" passes only when both sides pass.
package license

import (
	"fmt"
	"path"
	"strings"
)

// Package is one SBOM package and the licenses it declares. More than one
// entry means every entry applies, as if joined with AND.
type Package struct {
	Name     string
	Version  string
	PURL     string
	Licenses []string
}

// Policy is a set of license rules.
type Policy struct {
	// Deny patterns fail a license. Patterns are case-insensitive globs, so
	// "GPL-*" matches "GPL-3.0-only" but not "LGPL-2.1-only".
	Deny []string
	// Allow patterns, when set, fail every license that matches none of them.
	Allow []string
	// DenyUnknown fails a package that declares no license, or only
	// NOASSERTION or NONE.
	DenyUnknown bool
}

// Violation explains why a package failed.
type Violation struct {
	Package Package
	// License is the declared license that failed, or "" for an unknown one.
	License string
	Reason  string
}

func (v Violation) Error() string {
	name := v.Package.Name
	if v.Package.Version != "" {
		name += "@" + v.Package.Version
	}
	if v.License == "" {
		return fmt.Sprintf("%s: %s", name, v.Reason)
	}
	return fmt.Sprintf("%s: %s: %s", name, v.License, v.Reason)
}

// Check returns a violation for pkg, or false when it passes.
func (p Policy) Check(pkg Package) (Violation, bool) {
	known := knownLicenses(pkg.Licenses)
	if len(known) == 0 {
		if p.DenyUnknown {
			return Violation{Package: pkg, Reason: "no license declared"}, true
		}
		return Violation{}, false
	}
	for _, declared := range known {
		expr, err := Parse(declared)
		if err != nil {
			// An unparseable string is checked as one license name.
			expr = leaf{id: strings.TrimSpace(declared)}
		}
		if reason, ok := p.eval(expr); !ok {
			return Violation{Package: pkg, License: declared, Reason: reason}, true
		}
	}
	return Violation{}, false
}

func knownLicenses(values []string) []string {
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		switch strings.ToUpper(v) {
		case "", "NOASSERTION", "NONE", "UNKNOWN":
			continue
		}
		out = append(out, v)
	}
	return out
}

func (p Policy) eval(e Expr) (string, bool) {
	switch e := e.(type) {
	case and:
		for _, side := range []Expr{e.left, e.right} {
			if reason, ok := p.eval(side); !ok {
				return reason, false
			}
		}
		return "", true
	case or:
		left, ok := p.eval(e.left)
		if ok {
			return "", true
		}
		right, ok := p.eval(e.right)
		if ok {
			return "", true
		}
		return left + "; " + right, false
	case leaf:
		return p.leaf(e)
	default:
		return "unsupported expression", false
	}
}

func (p Policy) leaf(l leaf) (string, bool) {
	full := l.String()
	// An allow pattern for the exact "X WITH Y" form beats a deny for X.
	if l.exception != "" && matchAny(p.Allow, full) {
		return "", true
	}
	if pattern, ok := firstMatch(p.Deny, full, l.id); ok {
		return fmt.Sprintf("%s is denied by %q", full, pattern), false
	}
	if len(p.Allow) > 0 && !matchAny(p.Allow, full) && !matchAny(p.Allow, l.id) {
		return full + " is not in the allow list", false
	}
	return "", true
}

func matchAny(patterns []string, values ...string) bool {
	_, ok := firstMatch(patterns, values...)
	return ok
}

func firstMatch(patterns []string, values ...string) (string, bool) {
	for _, pattern := range patterns {
		pat := strings.ToLower(strings.TrimSpace(pattern))
		if pat == "" {
			continue
		}
		for _, v := range values {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" {
				continue
			}
			if ok, err := path.Match(pat, v); err == nil && ok {
				return pattern, true
			}
			if pat == v {
				return pattern, true
			}
		}
	}
	return "", false
}

// Expr is a parsed SPDX license expression.
type Expr interface {
	String() string
}

type leaf struct {
	id        string
	exception string
}

func (l leaf) String() string {
	if l.exception == "" {
		return l.id
	}
	return l.id + " WITH " + l.exception
}

type and struct{ left, right Expr }

func (a and) String() string { return "(" + a.left.String() + " AND " + a.right.String() + ")" }

type or struct{ left, right Expr }

func (o or) String() string { return "(" + o.left.String() + " OR " + o.right.String() + ")" }

// Parse reads an SPDX license expression. AND binds tighter than OR.
// Operators are case-insensitive.
func Parse(s string) (Expr, error) {
	p := &parser{tokens: tokenize(s)}
	if len(p.tokens) == 0 {
		return nil, fmt.Errorf("empty license expression")
	}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("unexpected %q in %q", p.tokens[p.pos], s)
	}
	return e, nil
}

func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '(', ')':
			flush()
			out = append(out, string(r))
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

type parser struct {
	tokens []string
	pos    int
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *parser) or() (Expr, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "OR") {
		p.pos++
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		left = or{left, right}
	}
	return left, nil
}

func (p *parser) and() (Expr, error) {
	left, err := p.term()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "AND") {
		p.pos++
		right, err := p.term()
		if err != nil {
			return nil, err
		}
		left = and{left, right}
	}
	return left, nil
}

func (p *parser) term() (Expr, error) {
	tok := p.peek()
	switch {
	case tok == "":
		return nil, fmt.Errorf("expression ends early")
	case tok == "(":
		p.pos++
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing )")
		}
		p.pos++
		return e, nil
	case tok == ")" || isOperator(tok):
		return nil, fmt.Errorf("unexpected %q", tok)
	}
	p.pos++
	l := leaf{id: tok}
	if strings.EqualFold(p.peek(), "WITH") {
		p.pos++
		exc := p.peek()
		if exc == "" || exc == "(" || exc == ")" || isOperator(exc) {
			return nil, fmt.Errorf("WITH needs an exception id")
		}
		p.pos++
		l.exception = exc
	}
	return l, nil
}

func isOperator(tok string) bool {
	return strings.EqualFold(tok, "AND") || strings.EqualFold(tok, "OR") || strings.EqualFold(tok, "WITH")
}

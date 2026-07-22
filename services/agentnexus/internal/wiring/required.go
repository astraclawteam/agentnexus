// Package wiring is the anti-regression guard for one defect class: a
// dependency is implemented, unit-tested, and never constructed by any
// composition root.
//
// Nothing crashes when that happens, because every one of these dependencies
// fails closed - the feature simply does not exist. The endpoint stays
// unregistered, the worker stays off the stream, the assistant is nil. Meanwhile
// the suite stays green, because every test sets the field itself and so never
// observes the production value. The gap is invisible from inside the package
// that owns the dependency and invisible from inside the tests that cover it;
// it is only visible at the composition root, which is where this package is
// meant to be called.
//
// The mechanism is deliberately two-sided. MissingRequired reports what a
// composition root left nil, and each caller pairs it with a map of the fields
// that may legitimately stay unset, every entry carrying a stated reason.
// StaleOptional then asserts that map is EXACT: every name must be a real field
// this package can actually inspect. That second assertion is what makes the
// guard maintainable rather than another list to forget, because adding a
// dependency forces a decision - wire it, or declare it optional and say why.
// Silence stops being an option. In AgentAtlas the same assertion immediately
// caught three optional entries naming concrete pointers, a kind the reflection
// never inspected, so listing them had been meaningless from the day they were
// written.
//
// This lives in its own package because three composition roots need it
// (cmd/gateway-api, cmd/connector-worker, cmd/gateway-agent) across three
// dependency-owning packages, and a per-package copy of the reflection would
// drift exactly the way the lists it guards drift.
package wiring

import (
	"reflect"
	"sort"
)

// Inspects reports whether MissingRequired can decide emptiness for a field of
// this kind.
//
// Only nilable dependency shapes qualify. A struct, string, int or slice field
// is a configuration VALUE, not a wired collaborator, and "unset" is not a
// question reflection can answer for it - the zero value is frequently the
// intended one. Callers whose dependency contract does include such a field
// (connector-worker's Identity is four required strings) must encode that
// requirement explicitly rather than expect it here; see
// worker.Config.MissingRequired.
//
// Pointers are inspected as well as interfaces and funcs. That is the one
// deliberate difference from the AgentAtlas original, which looked at interface
// and func kinds only: several dependencies in this repo are concrete pointer
// types, and a guard that silently skips them would report a fully wired
// composition while the pointer it never looked at was nil.
func Inspects(kind reflect.Kind) bool {
	switch kind {
	case reflect.Interface, reflect.Func, reflect.Pointer:
		return true
	}
	return false
}

// MissingRequired reports the inspectable dependency fields deps leaves nil,
// sorted and excluding every name in optional.
//
// An empty result means each dependency the composition root is contracted to
// supply is present. It does NOT mean any of them works: this is a wiring
// check, not a health check.
//
// deps must be a struct or a non-nil pointer to one. Anything else panics
// rather than returning an empty slice, because a guard that answers "nothing
// missing" when it was handed something it cannot read is the failure mode this
// package exists to prevent.
func MissingRequired(deps any, optional map[string]string) []string {
	value := structOf(deps, "wiring.MissingRequired")
	typ := value.Type()
	var missing []string
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() || !Inspects(field.Type.Kind()) {
			continue
		}
		if _, declared := optional[field.Name]; declared {
			continue
		}
		if value.Field(i).IsNil() {
			missing = append(missing, field.Name)
		}
	}
	sort.Strings(missing)
	return missing
}

// StaleOptional returns one human-readable complaint per entry of optional that
// does not describe a real, inspectable, reason-carrying field of deps. An empty
// result means the optional set is exact.
//
// A stale entry is not cosmetic. It silently downgrades a required dependency
// to optional - either because the field was renamed and the guard now skips
// nothing, or because the field is of a kind MissingRequired never looks at, so
// the entry always did nothing. Both are precisely how a wiring gap comes back.
func StaleOptional(deps any, optional map[string]string) []string {
	value := structOf(deps, "wiring.StaleOptional")
	typ := value.Type()
	fields := make(map[string]reflect.Kind, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		if field := typ.Field(i); field.IsExported() {
			fields[field.Name] = field.Type.Kind()
		}
	}
	var stale []string
	for name, reason := range optional {
		kind, exists := fields[name]
		switch {
		case !exists:
			stale = append(stale, name+" (no such exported field on "+typ.Name()+")")
		case !Inspects(kind):
			stale = append(stale, name+" (kind "+kind.String()+"; MissingRequired never inspects it, so this entry excludes nothing)")
		case reason == "":
			// The reason is the entire point of the entry. Without one the next
			// reader cannot tell a considered exemption from an oversight, and
			// the decision the exactness assertion forced is lost again.
			stale = append(stale, name+" (no stated reason for being optional)")
		}
	}
	sort.Strings(stale)
	return stale
}

func structOf(deps any, caller string) reflect.Value {
	value := reflect.ValueOf(deps)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			panic(caller + ": nil pointer")
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		panic(caller + ": want a struct or a pointer to one, got " + value.Kind().String())
	}
	return value
}

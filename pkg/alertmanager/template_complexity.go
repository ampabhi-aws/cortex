package alertmanager

import (
	"fmt"
	"reflect"
	"text/template/parse"

	"github.com/prometheus/alertmanager/config"
)

// Static-complexity bound on tenant-authored Alertmanager templates.
//
// Cortex renders tenant-authored templates inside a single shared
// process. Without this guard, validateUserConfig only bounded the
// static byte size of template files and did not inspect inline
// notifier template strings at all. A tenant could ship a tiny
// template with N nested range actions and, combined with M
// self-pushed alerts, cause O(M^N) iterations and output bytes to
// be produced in the notify pipeline, exhausting CPU and heap for
// every other tenant hosted by the same instance (CWE-400).
//
// This file provides a cheap AST walk that is applied at config
// upload time and rejects configs whose nesting of range, with and
// template actions exceeds a configured depth.

const errTemplateTooDeep = "template %q nesting depth %d exceeds limit %d"

type templateWithBody struct {
	name string
	body string
}

// knownFuncs lists function names used by Alertmanager templates so
// parse.Parse can validate call sites without rejecting them. The
// values are not invoked; only the names are consulted during parsing.
var knownFuncs = map[string]interface{}{
	"toUpper":      func() {},
	"toLower":      func() {},
	"title":        func() {},
	"join":         func() {},
	"match":        func() {},
	"safeHtml":     func() {},
	"reReplaceAll": func() {},
	"stringSlice":  func() {},
}

// templateNestingDepth returns the maximum nesting depth of range,
// with and template actions in the given template text. Non-parsable
// templates return (0, err); the caller is expected to also run the
// usual template.FromGlobs parse validation which produces a nicer
// error for genuine syntax errors.
func templateNestingDepth(name, text string) (int, error) {
	if text == "" {
		return 0, nil
	}
	trees, err := parse.Parse(name, text, "", "", knownFuncs)
	if err != nil {
		return 0, err
	}
	max := 0
	for _, t := range trees {
		if t == nil || t.Root == nil {
			continue
		}
		d := walkListDepth(t.Root, 0)
		if d > max {
			max = d
		}
	}
	return max, nil
}

func walkListDepth(list *parse.ListNode, cur int) int {
	if list == nil {
		return cur
	}
	max := cur
	for _, n := range list.Nodes {
		if d := walkNodeDepth(n, cur); d > max {
			max = d
		}
	}
	return max
}

func walkNodeDepth(n parse.Node, cur int) int {
	switch nn := n.(type) {
	case *parse.RangeNode:
		child := cur + 1
		max := child
		if d := walkListDepth(nn.List, child); d > max {
			max = d
		}
		if d := walkListDepth(nn.ElseList, child); d > max {
			max = d
		}
		return max
	case *parse.WithNode:
		child := cur + 1
		max := child
		if d := walkListDepth(nn.List, child); d > max {
			max = d
		}
		if d := walkListDepth(nn.ElseList, child); d > max {
			max = d
		}
		return max
	case *parse.TemplateNode:
		// template "name" is counted as a nesting step because it can
		// recurse into another parsed body at render time.
		return cur + 1
	case *parse.IfNode:
		max := cur
		if d := walkListDepth(nn.List, cur); d > max {
			max = d
		}
		if d := walkListDepth(nn.ElseList, cur); d > max {
			max = d
		}
		return max
	case *parse.ListNode:
		return walkListDepth(nn, cur)
	default:
		return cur
	}
}

// enforceTemplateComplexity walks every template body (both the
// uploaded template files and inline template strings embedded in
// receiver configs) and rejects configs whose nesting depth exceeds
// maxDepth. maxDepth <= 0 disables the check.
func enforceTemplateComplexity(amCfg *config.Config, cfgTemplates []templateWithBody, maxDepth int) error {
	if maxDepth <= 0 {
		return nil
	}
	for _, t := range cfgTemplates {
		d, err := templateNestingDepth(t.name, t.body)
		if err != nil {
			// Parse errors are already reported by the parse-only
			// template.FromGlobs validation; skip them here.
			continue
		}
		if d > maxDepth {
			return fmt.Errorf(errTemplateTooDeep, t.name, d, maxDepth)
		}
	}
	if amCfg != nil {
		for _, recv := range amCfg.Receivers {
			if recv == nil {
				continue
			}
			if err := checkReceiverTemplates(recv, maxDepth); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkReceiverTemplates(recv *config.Receiver, maxDepth int) error {
	return walkTemplateStrings(reflect.ValueOf(recv), recv.Name, maxDepth)
}

func walkTemplateStrings(v reflect.Value, ctx string, maxDepth int) error {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return walkTemplateStrings(v.Elem(), ctx, maxDepth)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			fv := v.Field(i)
			name := ctx + "." + f.Name
			if err := walkTemplateStrings(fv, name, maxDepth); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := walkTemplateStrings(v.Index(i), fmt.Sprintf("%s[%d]", ctx, i), maxDepth); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := walkTemplateStrings(iter.Value(), fmt.Sprintf("%s[%v]", ctx, iter.Key().Interface()), maxDepth); err != nil {
				return err
			}
		}
	case reflect.String:
		s := v.String()
		if s == "" {
			return nil
		}
		d, err := templateNestingDepth(ctx, s)
		if err != nil {
			// Not a template or malformed - leave to downstream parsing.
			return nil
		}
		if d > maxDepth {
			return fmt.Errorf(errTemplateTooDeep, ctx, d, maxDepth)
		}
	}
	return nil
}

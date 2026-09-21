package playbook

// Interpolation is fail-closed: a missing variable is an error, never "".
// This prevents wrong-target actions (empty iptables/mv/kill). Conditions
// support ==, !=, >=, <=, >, <, contains, and in_cidr.

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var varRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// Scope carries interpolation inputs. Investigation holds ${investigation.*}
// refs (id, intent, playbook, status) — no stubs.
type Scope struct {
	Input         map[string]any
	Results       map[string]any
	Investigation map[string]any
}

func interpolate(v any, scope *Scope) (any, error) {
	switch val := v.(type) {
	case string:
		return interpolateString(val, scope)
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, v := range val {
			iv, err := interpolate(v, scope)
			if err != nil {
				return nil, fmt.Errorf("interpolate key %s: %w", k, err)
			}
			out[k] = iv
		}
		return out, nil
	case []any:
		out := make([]any, len(val))
		for i, v := range val {
			iv, err := interpolate(v, scope)
			if err != nil {
				return nil, fmt.Errorf("interpolate index %d: %w", i, err)
			}
			out[i] = iv
		}
		return out, nil
	default:
		return v, nil
	}
}

func interpolateString(s string, scope *Scope) (string, error) {
	if !varRe.MatchString(s) {
		return s, nil
	}
	var firstErr error
	result := varRe.ReplaceAllStringFunc(s, func(match string) string {
		if firstErr != nil {
			return match
		}
		path := match[2 : len(match)-1]
		val, err := resolvePath(path, scope)
		if err != nil {
			firstErr = fmt.Errorf("resolve %s: %w", path, err)
			return match
		}
		return fmt.Sprintf("%v", val)
	})
	if firstErr != nil {
		return "", firstErr
	}
	return result, nil
}

func resolvePath(path string, scope *Scope) (any, error) {
	parts := strings.Split(path, ".")

	if len(parts) == 0 {
		return nil, fmt.Errorf("empty path")
	}

	switch parts[0] {
	case "input":
		if len(parts) < 2 {
			return nil, fmt.Errorf("input path too short")
		}
		return lookup(scope.Input, parts[1:])

	case "result":
		if len(parts) < 2 {
			return nil, fmt.Errorf("result path too short")
		}
		return lookup(scope.Results, parts[1:])

	case "outputs":
		if len(parts) < 4 {
			return nil, fmt.Errorf("outputs path requires agent.action.key, got %d parts", len(parts))
		}
		key := parts[1] + "." + parts[2]
		outputs, ok := scope.Results[key]
		if !ok {
			return nil, fmt.Errorf("no output for %s", key)
		}
		outputMap, ok := outputs.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("output for %s is not a map", key)
		}
		return lookup(outputMap, parts[3:])

	case "investigation":
		if len(parts) < 2 {
			return nil, fmt.Errorf("investigation path too short")
		}
		if scope.Investigation == nil {
			return nil, fmt.Errorf("no investigation in scope")
		}
		return lookup(scope.Investigation, parts[1:])

	default:
		return nil, fmt.Errorf("unknown scope: %s", parts[0])
	}
}

func lookup(m map[string]any, keys []string) (any, error) {
	current := m
	for i, key := range keys {
		val, ok := current[key]
		if !ok {
			return nil, fmt.Errorf("key %s not found", key)
		}
		if i == len(keys)-1 {
			return val, nil
		}
		next, ok := val.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("key %s is not a map", key)
		}
		current = next
	}
	return nil, fmt.Errorf("empty keys")
}

// condOp is a condition operator, longest-match first.
var condOps = []string{"!=", ">=", "<=", "==", ">", "<"}

func evaluateCondition(expr string, scope *Scope) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true, nil
	}

	if left, right, ok := splitKeywordOp(expr, " in_cidr "); ok {
		return evalCIDR(left, right, scope)
	}
	if left, right, ok := splitKeywordOp(expr, " contains "); ok {
		lv, err := interpolateString(strings.TrimSpace(left), scope)
		if err != nil {
			return false, fmt.Errorf("eval contains left: %w", err)
		}
		rv, err := interpOrLiteral(strings.TrimSpace(right), scope)
		if err != nil {
			return false, fmt.Errorf("eval contains right: %w", err)
		}
		return strings.Contains(lv, rv), nil
	}

	for _, op := range condOps {
		if idx := strings.Index(expr, op); idx >= 0 {
			left := strings.TrimSpace(expr[:idx])
			right := strings.TrimSpace(expr[idx+len(op):])
			lv, err := interpolateString(left, scope)
			if err != nil {
				return false, fmt.Errorf("eval left: %w", err)
			}
			rv, err := interpOrLiteral(right, scope)
			if err != nil {
				return false, fmt.Errorf("eval right: %w", err)
			}
			switch op {
			case "==":
				return lv == rv, nil
			case "!=":
				return lv != rv, nil
			default:
				return compareOrdered(lv, rv, op), nil
			}
		}
	}

	resolved, err := interpolateString(expr, scope)
	if err != nil {
		return false, fmt.Errorf("resolve expr: %w", err)
	}
	truthy, err := strconv.ParseBool(resolved)
	if err != nil {
		return resolved != "" && resolved != "0" && resolved != "false", nil
	}
	return truthy, nil
}

// interpOrLiteral interpolates ${...} refs, else treats the token as a
// literal with surrounding quotes trimmed.
func interpOrLiteral(tok string, scope *Scope) (string, error) {
	if varRe.MatchString(tok) {
		return interpolateString(tok, scope)
	}
	return strings.Trim(tok, "\" "), nil
}

func splitKeywordOp(expr, op string) (string, string, bool) {
	idx := strings.Index(expr, op)
	if idx < 0 {
		return "", "", false
	}
	return expr[:idx], expr[idx+len(op):], true
}

func compareOrdered(lv, rv, op string) bool {
	if lf, err1 := strconv.ParseFloat(lv, 64); err1 == nil {
		if rf, err2 := strconv.ParseFloat(rv, 64); err2 == nil {
			switch op {
			case ">=":
				return lf >= rf
			case "<=":
				return lf <= rf
			case ">":
				return lf > rf
			case "<":
				return lf < rf
			}
		}
	}
	switch op {
	case ">=":
		return lv >= rv
	case "<=":
		return lv <= rv
	case ">":
		return lv > rv
	case "<":
		return lv < rv
	}
	return false
}

func evalCIDR(left, right string, scope *Scope) (bool, error) {
	lv, err := interpolateString(strings.TrimSpace(left), scope)
	if err != nil {
		return false, fmt.Errorf("eval cidr left: %w", err)
	}
	rv, err := interpOrLiteral(strings.TrimSpace(right), scope)
	if err != nil {
		return false, fmt.Errorf("eval cidr right: %w", err)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(lv))
	if err != nil {
		return false, fmt.Errorf("cidr left is not an IP: %w", err)
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(rv))
	if err != nil {
		return false, fmt.Errorf("cidr right is not a CIDR: %w", err)
	}
	return prefix.Contains(addr), nil
}

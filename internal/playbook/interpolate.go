package playbook

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var varRe = regexp.MustCompile(`\$\{([^}]+)\}`)

type Scope struct {
	Input   map[string]any
	Results map[string]any
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

	result := varRe.ReplaceAllStringFunc(s, func(match string) string {
		path := match[2 : len(match)-1]
		val, err := resolvePath(path, scope)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("%v", val)
	})

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
		return nil, fmt.Errorf("investigation refs not yet supported")

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

func evaluateCondition(expr string, scope *Scope) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true, nil
	}

	if strings.Contains(expr, "==") {
		parts := strings.SplitN(expr, "==", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])

		leftVal, err := interpolateString(left, scope)
		if err != nil {
			return false, fmt.Errorf("eval left: %w", err)
		}

		rightVal := strings.Trim(right, "\" ")
		return leftVal == rightVal, nil
	}

	if strings.Contains(expr, "!=") {
		parts := strings.SplitN(expr, "!=", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])

		leftVal, err := interpolateString(left, scope)
		if err != nil {
			return false, fmt.Errorf("eval left: %w", err)
		}

		rightVal := strings.Trim(right, "\" ")
		return leftVal != rightVal, nil
	}

	resolved, err := interpolateString(expr, scope)
	if err != nil {
		return false, fmt.Errorf("resolve expr: %w", err)
	}

	if resolved == expr {
		return false, nil
	}

	truthy, err := strconv.ParseBool(resolved)
	if err != nil {
		return resolved != "" && resolved != "0" && resolved != "false", nil
	}

	return truthy, nil
}

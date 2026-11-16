package allowlist

import "testing"

func TestParseMountPoliciesJSON(t *testing.T) {
	policies, err := ParseMountPoliciesJSON([]byte(`{"app":{"policy":"deny"}}`))
	if err != nil || policies["app"].Policy != PolicyDeny {
		t.Fatalf("ParseMountPoliciesJSON() = %+v, %v, want app denied", policies, err)
	}
	for name, data := range map[string]string{
		"no policy":         `{"app":{}}`,
		"an unknown policy": `{"app":{"policy":"sometimes"}}`,
		"an unknown field":  `{"app":{"policy":"deny","surprise":1}}`,
		"a duplicate field": `{"app":{"policy":"deny","policy":"deny"}}`,
		"a duplicate name":  `{"app":{"policy":"deny"},"app":{"policy":"any"}}`,
		"a second document": `{"app":{"policy":"deny"}} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if policies, err := ParseMountPoliciesJSON([]byte(data)); err == nil {
				t.Errorf("ParseMountPoliciesJSON(%s) = %+v, want an error", data, policies)
			}
		})
	}
}

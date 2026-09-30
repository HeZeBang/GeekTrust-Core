package session

import (
	"reflect"
	"testing"

	"geektrust/internal/sdpc"
)

func TestGatewaySelectionCompatibility(t *testing.T) {
	policy := &sdpc.Resource{Gateways: []string{"a:441", "b:441"}, NodeGroups: map[string][]string{"g": {"a:441"}}, AppNodeGroups: map[string]string{"app": "g"}, MajorNodeGroup: "g"}
	for _, tt := range []struct {
		name, group      string
		override, legacy bool
		configured, want []string
	}{
		{"assigned", "g", false, false, []string{"a:441", "b:441"}, []string{"a:441"}},
		{"configured intersection", "g", true, true, []string{"a:441", "b:441"}, []string{"a:441"}},
		{"explicit alternate", "g", true, true, []string{"alternate:441"}, []string{"alternate:441"}},
		{"legacy missing group", "missing", false, true, []string{"a:441", "b:441"}, []string{"a:441", "b:441"}},
		{"strict missing group", "missing", false, false, []string{"a:441", "b:441"}, nil},
		{"no group", "", false, false, []string{"a:441", "b:441"}, []string{"a:441", "b:441"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Credential{Policy: policy, Gateways: tt.configured, GatewayOverride: tt.override, LegacyRouting: tt.legacy}
			if got := c.GatewaysForGroup(tt.group); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

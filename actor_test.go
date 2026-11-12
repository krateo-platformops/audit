package audit

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// ControllerActor reads the two downward-API variables: both set names the
// ServiceAccount; either unset, or not a name Kubernetes gives, names no
// principal.
func TestControllerActor(t *testing.T) {
	if EnvPodNamespace != "POD_NAMESPACE" || EnvPodServiceAccount != "POD_SERVICE_ACCOUNT" {
		t.Fatalf("env names = %q, %q: the charts set POD_NAMESPACE and POD_SERVICE_ACCOUNT", EnvPodNamespace, EnvPodServiceAccount)
	}
	unset := "\x00unset"
	for _, tc := range []struct {
		name, ns, sa, want string
	}{
		{"both set", "example-system", "example-controller", "system:serviceaccount:example-system:example-controller"},
		{"a dotted ServiceAccount name", "example-system", "example.controller", "system:serviceaccount:example-system:example.controller"},
		{"the namespace unset", unset, "example-controller", ""},
		{"the ServiceAccount unset", "example-system", unset, ""},
		{"both unset", unset, unset, ""},
		{"the namespace empty", "", "example-controller", ""},
		{"the ServiceAccount empty", "example-system", "", ""},
		{"a namespace not a DNS label: upper case", "Example-System", "example-controller", ""},
		{"a namespace not a DNS label: a dot", "example.system", "example-controller", ""},
		{"a namespace not a DNS label: a leading hyphen", "-example", "example-controller", ""},
		{"a namespace not a DNS label: 64 characters", strings.Repeat("a", 64), "example-controller", ""},
		{"a namespace of 63 characters", strings.Repeat("a", 63), "example-controller", "system:serviceaccount:" + strings.Repeat("a", 63) + ":example-controller"},
		{"a namespace with a colon", "example:system", "example-controller", ""},
		{"a ServiceAccount with a colon", "example-system", "example:controller", ""},
		{"a ServiceAccount in upper case", "example-system", "Example-Controller", ""},
		{"a ServiceAccount label ending in a hyphen", "example-system", "example-.controller", ""},
		{"a ServiceAccount with an empty label", "example-system", "example..controller", ""},
		{"a ServiceAccount ending in a dot", "example-system", "example.", ""},
		{"a ServiceAccount of 254 characters", "example-system", strings.Repeat("a", 254), ""},
		{"a ServiceAccount with a space", "example-system", "example controller", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for env, v := range map[string]string{EnvPodNamespace: tc.ns, EnvPodServiceAccount: tc.sa} {
				t.Setenv(env, "") // restored after the test
				if v == unset {
					unsetenv(t, env)
				} else {
					t.Setenv(env, v)
				}
			}
			if got := ControllerActor(); got != tc.want {
				t.Errorf("ControllerActor() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The actor ControllerActor names conforms where the schema reads it: an
// Emitter built as its doc says writes it as user.name of class controller,
// and with none, marks the record actor.
func TestControllerActor_TheDocumentedEmitter(t *testing.T) {
	ev := Event{Action: "example.reconcile", Verb: "update", Outcome: OutcomeSuccess, Resource: "configmaps",
		Namespace: "example-ns", Version: "v1", ObjectName: "example-object", StatusCode: 200}
	for _, tc := range []struct {
		name, ns, sa string
		wantActor    string
	}{
		{"set", "example-system", "example-controller", "system:serviceaccount:example-system:example-controller"},
		{"unset", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvPodNamespace, tc.ns)
			t.Setenv(EnvPodServiceAccount, tc.sa)
			opts := []Option{WithWriter(WriterController)}
			if actor := ControllerActor(); actor != "" {
				opts = append(opts, WithActor(actor, ClassController))
			}
			rec := &recorder{}
			lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(rec)))
			t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })
			e := New(lp.Logger("test"), opts...) // not newEmitter: it adds a test actor
			e.Emit(spanCtx(t), ev)
			got := attrs(only(t, rec))
			name, here := got[KeyUserName]
			if tc.wantActor == "" {
				if here {
					t.Errorf("user.name written with no actor")
				}
				if m := strings.Split(got[KeyIncomplete].AsString(), ","); !slices.Contains(m, "actor") {
					t.Errorf("incomplete = %v, want actor among them", m)
				}
				return
			}
			if name.AsString() != tc.wantActor || got[KeyActorClass].AsString() != string(ClassController) {
				t.Errorf("actor = %q (%s), want %q (controller)", name.AsString(), got[KeyActorClass].AsString(), tc.wantActor)
			}
		})
	}
}

// unsetenv unsets env for the rest of the test; the t.Setenv before it
// restores the old value after.
func unsetenv(t *testing.T, env string) {
	t.Helper()
	if err := os.Unsetenv(env); err != nil {
		t.Fatal(err)
	}
}

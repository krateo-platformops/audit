package audit

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
)

// The required keys per writer, written out by hand from the proposal's field
// table (installer#716 §1.2), so a wrong level in schema/v1.yaml or in the
// generator cannot pass unseen: the checker and the falsifier both read the
// generated table, and this list does not.
func TestSchema_RequiredKeysPerWriter(t *testing.T) {
	want := map[Writer][]string{
		WriterRequest: {"event.name", "krateo.audit.schema_version", "user.name", "krateo.action",
			"krateo.audit.verb", "http.request.method", "krateo.audit.outcome",
			"krateo.request.uri", "krateo.request.source_ips", "session.id"},
		WriterGateway: {"event.name", "krateo.audit.schema_version", "user.name", "krateo.action",
			"krateo.audit.verb", "http.request.method", "krateo.audit.outcome",
			"server.address", "krateo.request.source_ips", "krateo.audit.gateway.route"},
		WriterAction: {"event.name", "krateo.audit.schema_version", "user.name", "krateo.audit.actor_class",
			"krateo.action", "krateo.audit.verb", "krateo.audit.outcome"},
		WriterController: {"event.name", "krateo.audit.schema_version", "user.name", "krateo.audit.actor_class",
			"krateo.action", "krateo.audit.verb", "krateo.audit.outcome"},
	}
	for _, w := range Writers() {
		var got []string
		for _, k := range Keys() {
			if k.Writers[w].Level == LevelRequired {
				got = append(got, k.Name)
			}
		}
		slices.Sort(got)
		exp := slices.Clone(want[w])
		slices.Sort(exp)
		if !slices.Equal(got, exp) {
			t.Errorf("%s required keys:\n got %v\nwant %v", w, got, exp)
		}
	}
}

// Rulings D1, D2 and the gaps, as the schema states them.
func TestSchema_Rulings(t *testing.T) {
	get := func(k string) KeySpec {
		s, ok := LookupKey(k)
		if !ok {
			t.Fatalf("%s is not in the schema", k)
		}
		return s
	}
	// D1: a preview marker, a bool, that the gateway cannot establish.
	if p := get(KeyPreview); p.Type != TypeBool || p.Writers[WriterGateway].Level != LevelNotEstablished {
		t.Errorf("preview: %+v", p)
	}
	// D2: the actor class is the claim's four values; human and gateway
	// writers omit and mark it, controllers and tool executors always write it.
	ac := get(KeyActorClass)
	if !slices.Equal(ac.Values, []string{"human", "agent", "controller", "service"}) {
		t.Errorf("actor_class values = %v", ac.Values)
	}
	for _, w := range []Writer{WriterRequest, WriterGateway} {
		if r := ac.Writers[w]; r.Level != LevelConditional || !r.Markable || r.Check != "" {
			t.Errorf("actor_class for %s = %+v, want conditional on the claim, markable", w, r)
		}
	}
	// The renames, side by side.
	for old, cur := range map[string]string{
		"outcome": KeyOutcome, "k8s.resource.group": KeyObjectAPIGroup, "k8s.resource.version": KeyObjectAPIVersion,
		"k8s.resource.resource": KeyObjectResource, "k8s.resource.subresource": KeyObjectSubresource,
		"k8s.resource.kind": KeyObjectKind, "k8s.resource.name": KeyObjectName, "k8s.object.uid": KeyObjectUID,
		"k8s.object.generation": KeyObjectGeneration, "k8s.object.resource_version": KeyObjectResourceVersion,
		"enduser.id": KeyUserName,
	} {
		if got := get(old).ReplacedBy; got != cur {
			t.Errorf("%s replaced by %q, want %q", old, got, cur)
		}
		// enduser.id is written only where it is written today (snowplow, a
		// caller that sets EndUserID): Emit never adds it beside user.name.
		dual := old != "enduser.id"
		if get(old).DualWrite != dual {
			t.Errorf("%s: DualWrite = %v, want %v", old, get(old).DualWrite, dual)
		}
		if want := map[bool]string{true: old, false: ""}[dual]; LegacyKey(cur) != want {
			t.Errorf("LegacyKey(%s) = %q, want %q", cur, LegacyKey(cur), want)
		}
	}
	// Gap a, as ruled: a record is never dropped. user.name is required of
	// every writer, and markable: a record with no actor is emitted marked.
	for _, w := range Writers() {
		if r := get(KeyUserName).Writers[w]; r.Level != LevelRequired || !r.Markable || get(KeyUserName).Marker != "actor" {
			t.Errorf("user.name for %s = %+v, want required and markable as actor", w, r)
		}
	}
	// k8s.namespace.name is kept, and event.name stays as an attribute.
	get(KeyNamespace)
	if get(KeyEventName).Writers[WriterController].Level != LevelRequired {
		t.Errorf("event.name must stay required")
	}
	// method_original exists only beside _OTHER: required there, unexpected anywhere else.
	if mo := get(KeyHTTPMethodOriginal); mo.OnlyWhen != CondMethodOther || mo.Writers[WriterRequest].Check != CondMethodOther {
		t.Errorf("http.request.method_original: OnlyWhen %q, request check %q; want both %q", mo.OnlyWhen, mo.Writers[WriterRequest].Check, CondMethodOther)
	}
	// Gap d: a Kubernetes target always names its resource.
	if r := get(KeyObjectResource).Writers[WriterController]; r.Check != CondK8sTarget {
		t.Errorf("object_ref.resource for a controller = %+v, want it conditional on a Kubernetes target", r)
	}
}

func TestSchema_ClassesAndOutcomesMatchTheEnums(t *testing.T) {
	ac, _ := LookupKey(KeyActorClass)
	if got := []string{string(ClassHuman), string(ClassAgent), string(ClassController), string(ClassService)}; !slices.Equal(got, ac.Values) {
		t.Errorf("Class constants %v differ from the schema's %v", got, ac.Values)
	}
	for _, c := range ac.Values {
		if !Class(c).Known() {
			t.Errorf("Class(%q).Known() = false", c)
		}
	}
	oc, _ := LookupKey(KeyOutcome)
	if got := []string{OutcomeSuccess, OutcomeFailure, OutcomeDenied}; !slices.Equal(got, oc.Values) {
		t.Errorf("Outcome constants %v differ from the schema's %v", got, oc.Values)
	}
}

func TestSchema_EveryConditionHasARule(t *testing.T) {
	if len(Conditions()) == 0 {
		t.Fatal("no condition: the arm tests nothing")
	}
	for _, c := range Conditions() {
		if _, known := evalCondition(c, nil); !known {
			t.Errorf("condition %s has no rule in evalCondition", c)
		}
	}
	if _, known := evalCondition("no-such-condition", nil); known {
		t.Errorf("evalCondition knows a condition the schema does not declare")
	}
}

func TestSchema_IdentityAndAssertion(t *testing.T) {
	var identity []string
	for _, k := range Keys() {
		if k.Identity && k.Asserted {
			t.Errorf("%s is both identity and asserted", k.Name)
		}
		if k.Asserted != (strings.HasPrefix(k.Name, "krateo.audit.asserted.") || strings.HasPrefix(k.Name, clientPrefix)) {
			t.Errorf("%s: asserted keys, and only they, live under krateo.audit.asserted. or %s", k.Name, clientPrefix)
		}
		if k.Identity {
			identity = append(identity, k.Name)
		}
	}
	// installer#716 §4.1, plus enduser.id.
	want := []string{"user.name", "user.roles", "krateo.audit.on_behalf_of.user.name", "krateo.audit.delegation",
		"krateo.audit.impersonated_user.name", "krateo.audit.impersonated_user.roles",
		"krateo.audit.affected_user.name", "krateo.request.uri", "krateo.request.source_ips", "enduser.id"}
	slices.Sort(identity)
	slices.Sort(want)
	if !slices.Equal(identity, want) {
		t.Errorf("identity keys:\n got %v\nwant %v", identity, want)
	}
}

func TestSchema_EmbeddedYAMLIsTheFile(t *testing.T) {
	raw, err := os.ReadFile("schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(SchemaYAML(), raw) {
		t.Errorf("SchemaYAML() is not schema/v1.yaml")
	}
}

func TestSchema_AccessorsReturnCopies(t *testing.T) {
	k, _ := LookupKey(KeyVerb)
	k.Values[0] = "mutated"
	k.Writers[WriterRequest] = Requirement{}
	again, _ := LookupKey(KeyVerb)
	if again.Values[0] == "mutated" || again.Writers[WriterRequest].Level != LevelRequired {
		t.Errorf("LookupKey shares the schema table with its caller")
	}
	tr := Target()
	tr.Keys[0] = "mutated"
	if Target().Keys[0] == "mutated" {
		t.Errorf("Target shares the schema table with its caller")
	}
}

package audittest

import (
	"slices"

	"github.com/krateo-platformops/audit"
)

// ContentCase is one write of an object, before and after, and whether the
// AUDIT-4 ruling counts it as a content change. Before and After are the
// object as its JSON decodes (apiVersion, kind, metadata, spec), each a fresh
// copy: wrap them as an unstructured object to run a comparator on them.
type ContentCase struct {
	Name          string
	Before, After map[string]any
	Changed       bool
}

// undeclaredKey is a qualified key no schema list declares, as an annotation
// or as a label.
const undeclaredKey = "example.com/unrelated"

// AuthorizationMetadataCases returns the cases a content comparator must
// agree with on the authorization-bearing metadata (v0.13.0), derived from
// the schema's one list (audit.AuthorizationAnnotations, audit.AuthorizationLabels).
// The desired state is the same in every case, so only the metadata decides:
//
//   - each declared annotation, and each declared label, changed, added or
//     removed: a content change;
//   - an undeclared annotation or label changed, added or removed: not one;
//   - a declared key in the other kind (a declared annotation's key written as
//     a label, and the reverse) changed, added or removed: not one, since a
//     key counts only as the kind it is declared as.
//
// plumbing's kubeutil/content runs them against its comparator. Values are
// placeholders; none is an identity.
func AuthorizationMetadataCases() []ContentCase {
	var out []ContentCase
	edits := func(kind, key string, changed bool, why string) {
		for _, e := range []struct {
			name          string
			before, after map[string]string
		}{
			{"changed", map[string]string{key: "example-a"}, map[string]string{key: "example-b"}},
			{"added", nil, map[string]string{key: "example-a"}},
			{"removed", map[string]string{key: "example-a"}, nil},
		} {
			out = append(out, ContentCase{
				Name:    why + " " + kind + " " + key + " " + e.name,
				Before:  contentObject(kind, e.before),
				After:   contentObject(kind, e.after),
				Changed: changed,
			})
		}
	}
	declared := map[string][]string{"annotation": audit.AuthorizationAnnotations(), "label": audit.AuthorizationLabels()}
	other := map[string]string{"annotation": "label", "label": "annotation"}
	for _, kind := range []string{"annotation", "label"} {
		for _, k := range declared[kind] {
			edits(kind, k, true, "a declared")
			if !slices.Contains(declared[other[kind]], k) {
				edits(other[kind], k, false, "a declared "+kind+"'s key as")
			}
		}
		edits(kind, undeclaredKey, false, "an undeclared")
	}
	return out
}

// contentObject is an object whose metadata carries m as its annotations or
// labels (kind), and none of the other.
func contentObject(kind string, m map[string]string) map[string]any {
	meta := map[string]any{"name": "example", "namespace": "example-ns"}
	if m != nil {
		v := map[string]any{}
		for k, s := range m {
			v[k] = s
		}
		meta[map[string]string{"annotation": "annotations", "label": "labels"}[kind]] = v
	}
	return map[string]any{
		"apiVersion": "example.krateo.io/v1",
		"kind":       "Example",
		"metadata":   meta,
		"spec":       map[string]any{"replicas": int64(1)},
	}
}

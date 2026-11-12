package audit

import "os"

// The downward-API variables a controller's chart sets, from which the
// controller names itself as the actor of its records (v0.12.0). The chart
// sets both from the pod's own fields, never from a value:
//
//	env:
//	  - name: POD_NAMESPACE
//	    valueFrom:
//	      fieldRef:
//	        fieldPath: metadata.namespace
//	  - name: POD_SERVICE_ACCOUNT
//	    valueFrom:
//	      fieldRef:
//	        fieldPath: spec.serviceAccountName
const (
	EnvPodNamespace      = "POD_NAMESPACE"
	EnvPodServiceAccount = "POD_SERVICE_ACCOUNT"
)

// ControllerActor returns the controller's own principal,
// system:serviceaccount:<namespace>:<name>, read from EnvPodNamespace and
// EnvPodServiceAccount: ServiceAccountActor of the two.
//
// It returns "" when either is unset (a local run) or not a name Kubernetes
// would give (the downward API always yields one; anything else was set by
// hand). The controller then passes no WithActor, and Emit marks every record
// krateo.audit.incomplete=actor, rather than naming a principal it is not:
//
//	opts := []audit.Option{audit.WithWriter(audit.WriterController)}
//	if actor := audit.ControllerActor(); actor != "" {
//		opts = append(opts, audit.WithActor(actor, audit.ClassController))
//	}
//	emitter := audit.New(logger, opts...)
func ControllerActor() string {
	return ServiceAccountActor(os.Getenv(EnvPodNamespace), os.Getenv(EnvPodServiceAccount))
}

// ServiceAccountActor returns system:serviceaccount:<namespace>:<name>, the
// username Kubernetes gives ServiceAccount name in namespace, or "" when
// namespace is not a DNS-1123 label (format k8s_namespace) or name is not a
// DNS-1123 subdomain (a ServiceAccount's name rule): an empty, mis-cased or
// colon-bearing part never yields a principal.
func ServiceAccountActor(namespace, name string) string {
	if !ValidK8sNamespace(namespace) || !validDNSSubdomain(name) {
		return ""
	}
	return "system:serviceaccount:" + namespace + ":" + name
}

// validDNSSubdomain is Kubernetes' DNS-1123 subdomain: at most 253
// characters, dot-separated labels of [a-z0-9-], each starting and ending
// with a letter or digit.
func validDNSSubdomain(v string) bool {
	if len(v) == 0 || len(v) > 253 {
		return false
	}
	alnum := func(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }
	start := 0
	for i := 0; i <= len(v); i++ {
		if i < len(v) && v[i] != '.' {
			if c := v[i]; !alnum(c) && c != '-' {
				return false
			}
			continue
		}
		if i == start || !alnum(v[start]) || !alnum(v[i-1]) {
			return false
		}
		start = i + 1
	}
	return true
}

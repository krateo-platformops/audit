package audit

import (
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// v0.15.0: the verified identity's claim on authn's sign-ins (audit#37),
// the audience of a /delegate token and two more request denial reasons
// (authn#155, the rulings on audit#37), and the public actor class
// (audit#38).

// exampleClaims are claims as authn's storage.EncodeClaim writes them, one
// per sign-in strategy (authn's login.go files set the subject: basic
// {namespace, name}, LDAP {config, DN}, OAuth {config, subject}, OIDC
// {issuer, subject}, ServiceAccount {mapping namespace, mapping name}).
var exampleClaims = map[string]string{
	"basic":          `["basic","example-system","example-user"]`,
	"ldap":           `["ldap","example-ldap","uid=example-user,ou=people,dc=example,dc=com"]`,
	"oauth":          `["oauth","example-github","12345678"]`,
	"oidc":           `["oidc","https://idp.example.com/realms/krateo","00000000-0000-4000-8000-000000000001"]`,
	"serviceaccount": `["serviceaccount","example-system","example-mapping"]`,
}

// signInRecord is authn's record of a sign-in with strategy: an update of
// the user's credential Secret, carrying the verified identity's claim.
func signInRecord(strategy string) []attribute.KeyValue {
	action := "authn.login." + strategy
	return with(onObject(baseRecord(WriterRequest), "", "secrets", ""),
		attribute.String(KeyAction, action), attribute.String(KeyVerb, "update"), attribute.String(KeyHTTPMethod, "PUT"),
		attribute.Int(KeyHTTPStatusCode, 200),
		attribute.String(KeyNamespace, "example-system"),
		attribute.String(KeyObjectName, "example-user-clientconfig"), attribute.String(KeyLegacyResourceName, "example-user-clientconfig"),
		attribute.String(KeyRequestURI, "/"+strategy+"/login"),
		attribute.String(KeyIdentityClaim, exampleClaims[strategy]))
}

// delegateRecord is authn's record of a /delegate exchange that issued a
// token: a create on the actor mapping's token subresource, no status code
// (authn issues the token itself), the subject on on_behalf_of and in the
// chain.
func delegateRecord() []attribute.KeyValue {
	return with(without(onObject(baseRecord(WriterRequest), "serviceaccount.authn.krateo.io", "serviceaccounts", "token"),
		KeyHTTPStatusCode, KeyUserRoles),
		attribute.String(KeyUserName, "example-agent"), attribute.String(KeyLegacyEndUserID, "example-agent"),
		attribute.String(KeyActorClass, string(ClassService)),
		attribute.String(KeyOnBehalfOf, "example-user"),
		attribute.StringSlice(KeyDelegation, []string{"service:example-agent", "human:example-user"}),
		attribute.String(KeyAction, "authn.delegate"), attribute.String(KeyVerb, "create"), attribute.String(KeyHTTPMethod, "POST"),
		attribute.String(KeyNamespace, "example-system"),
		attribute.String(KeyObjectAPIVersion, "v1alpha1"), attribute.String(KeyLegacyResourceVersion, "v1alpha1"),
		attribute.String(KeyObjectName, "example-agent"), attribute.String(KeyLegacyResourceName, "example-agent"),
		attribute.String(KeyRequestURI, "/delegate"))
}

// delegateRefusal is delegateRecord refused by authn with reason.
func delegateRefusal(reason string) []attribute.KeyValue {
	return with(deniedRecord(delegateRecord()), attribute.String(KeyDenialReason, reason))
}

// subjectSecretRefusal is a /delegate refusal of an identity provider's
// subject token over the subject username's credential Secret, which it
// names as a login record does (authn#155): no status code.
func subjectSecretRefusal(reason string) []attribute.KeyValue {
	return with(deniedRecord(onObject(without(delegateRecord(), KeyObjectAPIVersion, KeyLegacyResourceVersion), "", "secrets", "")),
		attribute.String(KeyObjectAPIVersion, "v1"), attribute.String(KeyLegacyResourceVersion, "v1"),
		attribute.String(KeyObjectName, "example-user-clientconfig"), attribute.String(KeyLegacyResourceName, "example-user-clientconfig"),
		attribute.String(KeyDenialReason, reason))
}

// publicRecord is snowplow's record of a write a request with no
// credential at all made, served as its public identity (snowplow#1393).
func publicRecord() []attribute.KeyValue {
	return with(baseRecord(WriterRequest),
		attribute.String(KeyUserName, "krateo:public"), attribute.String(KeyLegacyEndUserID, "krateo:public"),
		attribute.StringSlice(KeyUserRoles, []string{"system:unauthenticated"}),
		attribute.String(KeyActorClass, string(ClassPublic)))
}

type v15Case struct {
	name  string
	w     Writer
	attrs []attribute.KeyValue
	want  []Violation
}

func runV15(t *testing.T, cases []v15Case) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}
}

func v15v(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }

// The claim: on every sign-in strategy and outcome, of its format, the
// request writer's only, and never beside the public class.
func TestCheck_IdentityClaim(t *testing.T) {
	var cases []v15Case
	for _, s := range signInStrategies {
		rec := signInRecord(s)
		cases = append(cases,
			v15Case{s + ": a success", WriterRequest, rec, nil},
			v15Case{s + ": denied, name_claimed", WriterRequest,
				with(deniedRecord(rec), attribute.String(KeyDenialReason, DenialReasonNameClaimed)), nil},
			v15Case{s + ": a failure", WriterRequest,
				with(rec, attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure), attribute.Int(KeyHTTPStatusCode, 503)), nil},
		)
	}
	rec := signInRecord("oidc")
	claim := func(v string) []attribute.KeyValue { return with(rec, attribute.String(KeyIdentityClaim, v)) }
	cases = append(cases,
		v15Case{"step-up carries the session's claim", WriterRequest, with(rec, attribute.String(KeyAction, "authn.stepup.oidc")), nil},
		v15Case{"name_missing: the Secret resource, no name, still the claim", WriterRequest,
			with(without(deniedRecord(rec), KeyObjectName, KeyLegacyResourceName), attribute.String(KeyDenialReason, DenialReasonNameMissing)), nil},
		v15Case{"absent: optional", WriterRequest, without(rec, KeyIdentityClaim), nil},
		v15Case{"not JSON", WriterRequest, claim("oidc|https://idp.example.com|sub"), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"two elements", WriterRequest, claim(`["oidc","sub"]`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"four elements", WriterRequest, claim(`["oidc","iss","sub","x"]`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"a JSON object", WriterRequest, claim(`{"strategy":"oidc","issuer":"iss","subject":"sub"}`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"a number for the subject", WriterRequest, claim(`["oidc","iss",1]`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"a strategy no sign-in verifies", WriterRequest, claim(`["self","iss","sub"]`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"a strategy in another case", WriterRequest, claim(`["OIDC","iss","sub"]`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"an empty subject", WriterRequest, claim(`["oidc","iss",""]`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"spaces EncodeClaim never writes", WriterRequest, claim(`["oidc", "iss", "sub"]`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"an escape EncodeClaim never writes", WriterRequest, claim(`["oidc","iss","\u0073ub"]`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"trailing data", WriterRequest, claim(`["oidc","iss","sub"]x`), []Violation{v15v(KeyIdentityClaim, ReasonBadFormat)}},
		v15Case{"empty", WriterRequest, claim(""), []Violation{v15v(KeyIdentityClaim, ReasonEmpty)}},
		v15Case{"beside the public class", WriterRequest, with(rec, attribute.String(KeyActorClass, string(ClassPublic))),
			[]Violation{v15v(KeyIdentityClaim, ReasonUnexpected)}},
		v15Case{"on the gateway", WriterGateway, with(baseRecord(WriterGateway), attribute.String(KeyIdentityClaim, exampleClaims["oidc"])),
			[]Violation{v15v(KeyIdentityClaim, ReasonNotForWriter)}},
		v15Case{"on an action record", WriterAction, with(baseRecord(WriterAction), attribute.String(KeyIdentityClaim, exampleClaims["oidc"])),
			[]Violation{v15v(KeyIdentityClaim, ReasonNotForWriter)}},
		v15Case{"on a controller", WriterController, with(baseRecord(WriterController), attribute.String(KeyIdentityClaim, exampleClaims["oidc"])),
			[]Violation{v15v(KeyIdentityClaim, ReasonNotForWriter)}},
	)
	runV15(t, cases)

	k, ok := LookupKey(KeyIdentityClaim)
	if !ok || !k.Identity || k.Asserted || k.Type != TypeString || k.Format != FormatIdentityClaim || k.NotWhen != CondPublicActor || k.OnlyWhen != "" {
		t.Errorf("identity.claim: %+v", k)
	}
	for _, w := range Writers() {
		r := k.Writers[w]
		if w == WriterRequest {
			if r.Level != LevelConditional || r.Check != "" || r.Markable {
				t.Errorf("request: %+v, want conditional on what the record can't show, unmarked", r)
			}
		} else if r.Level != LevelNotApplicable {
			t.Errorf("%s: %v, want not applicable", w, r.Level)
		}
	}
}

// The audience: on an issued token or an audience_not_allowed refusal, of
// format token_audience, and nowhere else.
func TestCheck_TokenAudience(t *testing.T) {
	issued := delegateRecord()
	aud := func(rec []attribute.KeyValue, v string) []attribute.KeyValue {
		return with(rec, attribute.String(KeyTokenAudience, v))
	}
	refused := delegateRefusal(DenialReasonAudienceNotAllowed)
	bad := []Violation{v15v(KeyTokenAudience, ReasonBadFormat)}
	cases := []v15Case{
		{"issued, no audience requested", WriterRequest, issued, nil},
		{"issued for a DNS label", WriterRequest, aud(issued, "agentiko"), nil},
		{"issued for a DNS subdomain", WriterRequest, aud(issued, "agentiko.example.com"), nil},
		{"issued for a 253-character subdomain", WriterRequest, aud(issued, strings.Repeat("a", 63)+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 63)+"."+strings.Repeat("d", 61)), nil},
		{"issued for an https URI", WriterRequest, aud(issued, "https://agentiko.example.com"), nil},
		{"issued for an https URI with a port and a path", WriterRequest, aud(issued, "https://agentiko.example.com:8443/mcp/v1"), nil},
		{"audience_not_allowed with the requested audience", WriterRequest, aud(refused, "other.example.com"), nil},
		{"audience_not_allowed without it", WriterRequest, refused, nil},
		{"invalid_request without the value", WriterRequest, delegateRefusal(DenialReasonInvalidRequest), nil},

		{"uppercase", WriterRequest, aud(issued, "Agentiko"), bad},
		{"too long: 254 characters", WriterRequest, aud(issued, strings.Repeat("a", 63)+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 63)+"."+strings.Repeat("d", 62)), bad},
		{"a label longer than 63 is still a subdomain's", WriterRequest, aud(issued, strings.Repeat("a", 64)), nil},
		{"an underscore", WriterRequest, aud(issued, "agentiko_x"), bad},
		{"a leading hyphen", WriterRequest, aud(issued, "-agentiko"), bad},
		{"an empty label", WriterRequest, aud(issued, "agentiko..example"), bad},
		{"a query", WriterRequest, aud(issued, "https://agentiko.example.com/?tenant=a"), bad},
		{"an empty query", WriterRequest, aud(issued, "https://agentiko.example.com/?"), bad},
		{"a fragment", WriterRequest, aud(issued, "https://agentiko.example.com/#a"), bad},
		{"userinfo", WriterRequest, aud(issued, "https://user@agentiko.example.com"), bad},
		{"userinfo with a password", WriterRequest, aud(issued, "https://u:p@agentiko.example.com"), bad},
		{"http", WriterRequest, aud(issued, "http://agentiko.example.com"), bad},
		{"https in another case", WriterRequest, aud(issued, "HTTPS://agentiko.example.com"), bad},
		{"no host", WriterRequest, aud(issued, "https:///mcp"), bad},
		{"only a port", WriterRequest, aud(issued, "https://:8443"), bad},
		{"a space", WriterRequest, aud(issued, "https://agentiko.example.com/a b"), bad},
		{"not ASCII", WriterRequest, aud(issued, "https://agentikö.example.com"), bad},
		{"free text", WriterRequest, aud(issued, "the agentiko bridge"), bad},
		{"empty", WriterRequest, aud(issued, ""), []Violation{v15v(KeyTokenAudience, ReasonEmpty)}},

		{"on invalid_request", WriterRequest, aud(delegateRefusal(DenialReasonInvalidRequest), "agentiko"), []Violation{v15v(KeyTokenAudience, ReasonUnexpected)}},
		{"on another refusal", WriterRequest, aud(delegateRefusal(DenialReasonSubjectTokenInvalid), "agentiko"), []Violation{v15v(KeyTokenAudience, ReasonUnexpected)}},
		{"on a denied record with no reason", WriterRequest, aud(deniedRecord(issued), "agentiko"), []Violation{v15v(KeyTokenAudience, ReasonUnexpected)}},
		{"on a failure", WriterRequest, aud(with(issued, attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure)), "agentiko"),
			[]Violation{v15v(KeyTokenAudience, ReasonUnexpected)}},
		{"on the gateway", WriterGateway, aud(baseRecord(WriterGateway), "agentiko"), []Violation{v15v(KeyTokenAudience, ReasonNotForWriter)}},
		{"on a controller", WriterController, aud(baseRecord(WriterController), "agentiko"), []Violation{v15v(KeyTokenAudience, ReasonNotForWriter)}},
	}
	runV15(t, cases)

	k, ok := LookupKey(KeyTokenAudience)
	if !ok || k.Identity || k.Asserted || k.Type != TypeString || k.Format != FormatTokenAudience || k.OnlyWhen != CondIssuedOrAudienceRefused || len(k.Values) != 0 {
		t.Errorf("token.audience: %+v", k)
	}
	for _, w := range Writers() {
		r := k.Writers[w]
		if w == WriterRequest {
			if r.Level != LevelConditional || r.Check != "" || len(r.Values) != 0 {
				t.Errorf("request: %+v, want conditional on what the record can't show, bounded by format only", r)
			}
		} else if r.Level != LevelNotApplicable {
			t.Errorf("%s: %v, want not applicable", w, r.Level)
		}
	}
	for _, tc := range []struct {
		attrs []attribute.KeyValue
		want  bool
	}{
		{issued, true},
		{refused, true},
		{delegateRefusal(DenialReasonInvalidRequest), false},
		{deniedRecord(issued), false},
		{with(issued, attribute.String(KeyOutcome, OutcomeFailure)), false},
		{without(issued, KeyOutcome), false},
	} {
		if got := Holds(CondIssuedOrAudienceRefused, tc.attrs); got != tc.want {
			t.Errorf("issued_or_audience_refused on %v = %v, want %v", attrs2map(tc.attrs), got, tc.want)
		}
	}
}

func attrs2map(a []attribute.KeyValue) map[string]string {
	m := map[string]string{}
	for _, kv := range a {
		if kv.Key == KeyOutcome || kv.Key == KeyDenialReason {
			m[string(kv.Key)] = kv.Value.Emit()
		}
	}
	return m
}

// subject_not_signed_in and audience_not_allowed: the request writer's
// denial reasons, never beside a status code (no authority answered). The
// existing reasons authn#155 maps onto /delegate stay accepted there.
func TestCheck_DelegateDenialReasons(t *testing.T) {
	if DenialReasonSubjectNotSignedIn != "subject_not_signed_in" || DenialReasonAudienceNotAllowed != "audience_not_allowed" {
		t.Errorf("constants %q, %q", DenialReasonSubjectNotSignedIn, DenialReasonAudienceNotAllowed)
	}
	var cases []v15Case
	for _, reason := range []string{DenialReasonSubjectNotSignedIn, DenialReasonNameHeldLegacy, DenialReasonNameClaimed} {
		rec := subjectSecretRefusal(reason)
		cases = append(cases,
			v15Case{reason + ": names the username's Secret", WriterRequest, rec, nil},
			v15Case{reason + ": with a status code", WriterRequest, with(rec, attribute.Int(KeyHTTPStatusCode, 403)), []Violation{v15v(KeyHTTPStatusCode, ReasonUnexpected)}},
		)
	}
	for _, reason := range []string{DenialReasonPlatformGroup, DenialReasonGroupNotAllowed, DenialReasonSubjectTokenInvalid, DenialReasonAudienceNotAllowed} {
		cases = append(cases, v15Case{reason + " on /delegate", WriterRequest, delegateRefusal(reason), nil})
	}
	for _, reason := range []string{DenialReasonSubjectNotSignedIn, DenialReasonAudienceNotAllowed} {
		cases = append(cases,
			v15Case{reason + ": with a status code", WriterRequest, with(delegateRefusal(reason), attribute.Int(KeyHTTPStatusCode, 400)), []Violation{v15v(KeyHTTPStatusCode, ReasonUnexpected)}},
			v15Case{reason + ": on a success", WriterRequest, with(delegateRecord(), attribute.String(KeyDenialReason, reason)), []Violation{v15v(KeyDenialReason, ReasonUnexpected)}},
			v15Case{reason + ": on a controller", WriterController, with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, reason)), []Violation{v15v(KeyDenialReason, ReasonBadEnum)}},
			v15Case{reason + ": on the gateway", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, reason)), []Violation{v15v(KeyDenialReason, ReasonNotForWriter)}},
		)
	}
	runV15(t, cases)
	d, _ := LookupKey(KeyDenialReason)
	for _, r := range []string{"subject_not_signed_in", "audience_not_allowed"} {
		if !slices.Contains(d.Writers[WriterRequest].Values, r) || slices.Contains(d.Writers[WriterController].Values, r) {
			t.Errorf("%s: the request writer's value only", r)
		}
	}
}

// The public class: the request writer's only, never a credential's, and
// never beside a key that names a person.
func TestCheck_PublicActor(t *testing.T) {
	pub := publicRecord()
	read := with(without(pub, KeyDryRun), attribute.String(KeyVerb, "get"), attribute.String(KeyHTTPMethod, "GET"), attribute.Int(KeyHTTPStatusCode, 200))
	cases := []v15Case{
		{"a public visitor's write", WriterRequest, pub, nil},
		{"a public visitor's read", WriterRequest, read, nil},
		{"the public identity it impersonated", WriterRequest,
			with(pub, attribute.String(KeyImpersonatedUser, "krateo:public"), attribute.StringSlice(KeyImpersonatedRoles, []string{"system:unauthenticated"})), nil},
		{"refused by RBAC on a path", WriterRequest,
			with(without(deniedRecord(pub), KeyNamespace, KeyObjectAPIVersion, KeyLegacyResourceVersion, KeyObjectResource, KeyLegacyResourceResource,
				KeyObjectName, KeyLegacyResourceName, KeyPreview), attribute.String(KeyURLPath, "/debug/shadow-parity"), attribute.String(KeyVerb, "post"),
				attribute.String(KeyDenialReason, DenialReasonRbacNotAllowed)), nil},
		{"beside on_behalf_of", WriterRequest, with(pub, attribute.String(KeyOnBehalfOf, "example-user")),
			[]Violation{v15v(KeyOnBehalfOf, ReasonUnexpected), v15v(KeyDelegation, ReasonMissing)}},
		{"beside a delegation", WriterRequest, with(pub, attribute.String(KeyOnBehalfOf, "example-user"), attribute.StringSlice(KeyDelegation, []string{"agent:example-agent", "human:example-user"})),
			[]Violation{v15v(KeyOnBehalfOf, ReasonUnexpected), v15v(KeyDelegation, ReasonUnexpected)}},
		{"beside a verified claim", WriterRequest, with(pub, attribute.String(KeyIdentityClaim, exampleClaims["oidc"])),
			[]Violation{v15v(KeyIdentityClaim, ReasonUnexpected)}},
		{"on the gateway", WriterGateway, with(baseRecord(WriterGateway), attribute.String(KeyActorClass, string(ClassPublic))), []Violation{v15v(KeyActorClass, ReasonBadEnum)}},
		{"on an action record", WriterAction, with(baseRecord(WriterAction), attribute.String(KeyActorClass, string(ClassPublic))), []Violation{v15v(KeyActorClass, ReasonBadEnum)}},
		{"on a controller", WriterController, with(baseRecord(WriterController), attribute.String(KeyActorClass, string(ClassPublic))), []Violation{v15v(KeyActorClass, ReasonBadEnum)}},
		{"in another case", WriterRequest, with(pub, attribute.String(KeyActorClass, "Public")), []Violation{v15v(KeyActorClass, ReasonBadEnum)}},
		{"a delegation link of the public class", WriterRequest,
			with(delegateRecord(), attribute.StringSlice(KeyDelegation, []string{"public:example-agent", "human:example-user"})),
			[]Violation{v15v(KeyDelegation, ReasonBadFormat)}},
		// A delegated person's record keeps on_behalf_of and delegation.
		{"a human's delegated record", WriterRequest, delegateRecord(), nil},
	}
	runV15(t, cases)

	if !Holds(CondPublicActor, pub) || Holds(CondPublicActor, baseRecord(WriterRequest)) || Holds(CondPublicActor, without(pub, KeyActorClass)) {
		t.Error("condition public_actor does not hold exactly on actor class public")
	}
	if ClassPublic.Known() {
		t.Error("ClassPublic is Known: it would be read from a credential's claim")
	}
	for _, claim := range []string{"public", "Public"} {
		if c, ok := ParseClaim(claim); ok {
			t.Errorf("ParseClaim(%q) = %q, true; no credential carries the public class", claim, c)
		}
	}
	if ValidDelegationLink("public:example-agent") {
		t.Error("a delegation link of the public class is valid")
	}
	for _, k := range []string{KeyIdentityClaim, KeyOnBehalfOf, KeyDelegation} {
		if s, _ := LookupKey(k); s.NotWhen != CondPublicActor {
			t.Errorf("%s: not_when %q, want %q", k, s.NotWhen, CondPublicActor)
		}
	}
	// impersonated_user.* names whom the writer impersonated: the public
	// identity itself, never a person, so it stays allowed.
	for _, k := range []string{KeyImpersonatedUser, KeyImpersonatedRoles} {
		if s, _ := LookupKey(k); s.NotWhen != "" {
			t.Errorf("%s: not_when %q, want none", k, s.NotWhen)
		}
	}
}

// The actor class's closed sets, per writer, by hand: the four credential
// classes everywhere, public for the request writer only.
func TestSchema_ActorClassSetsPerWriter(t *testing.T) {
	four := []string{"human", "agent", "controller", "service"}
	want := map[Writer][]string{
		WriterRequest:    append(slices.Clone(four), "public"),
		WriterGateway:    four,
		WriterAction:     four,
		WriterController: four,
	}
	ac, _ := LookupKey(KeyActorClass)
	if len(ac.Values) != 0 {
		t.Errorf("actor_class has key-level values %v: its sets are per writer", ac.Values)
	}
	for w, vs := range want {
		if got := ac.Writers[w].Values; !slices.Equal(got, vs) {
			t.Errorf("%s: actor_class values %v, want %v", w, got, vs)
		}
	}
	if ActorClassPublic != string(ClassPublic) || ActorClassHuman != string(ClassHuman) {
		t.Errorf("generated constants %q, %q differ from the Class constants", ActorClassPublic, ActorClassHuman)
	}
}

// The two formats, through their exported validators and ValidValue.
func TestValidFormat_IdentityClaimAndTokenAudience(t *testing.T) {
	for s, claim := range exampleClaims {
		if !ValidIdentityClaim(claim) {
			t.Errorf("%s: %s is not a valid claim", s, claim)
		}
		if err := ValidValue(KeyIdentityClaim, claim); err != nil {
			t.Errorf("ValidValue(%s): %v", s, err)
		}
	}
	// An HTML character, a quote and a backslash, as encoding/json escapes
	// them: the canonical form is accepted, the raw one refused.
	if !ValidIdentityClaim(`["oidc","https://idp.example.com/a\u0026b","x\"y\\z"]`) {
		t.Error("the canonical escapes are refused")
	}
	if ValidIdentityClaim(`["oidc","https://idp.example.com/a&b","sub"]`) {
		t.Error("an & encoding/json escapes is accepted raw")
	}
	for _, v := range []string{"agentiko", "a", "agentiko.example.com", "https://agentiko.example.com", "https://10.0.0.1:8443/x", "https://[2001:db8::1]/x"} {
		if !ValidTokenAudience(v) {
			t.Errorf("%q is not a valid audience", v)
		}
	}
	for _, v := range []string{"", "Agentiko", "agentiko.", ".agentiko", "https://agentiko.example.com?x", "https://u@agentiko.example.com", "ftp://agentiko.example.com", "https:agentiko"} {
		if ValidTokenAudience(v) {
			t.Errorf("%q is a valid audience", v)
		}
	}
	err := ValidValue(KeyTokenAudience, "Agentiko")
	if fe, ok := err.(*FormatError); !ok || fe.Format != FormatTokenAudience || strings.Contains(err.Error(), "Agentiko") {
		t.Errorf("ValidValue(token.audience, uppercase) = %v, want a FormatError naming the format, never the value", err)
	}
}

// Emit writes the claim and the audience when they are of their formats,
// omits them (unmarked: they are optional) when not, and writes the public
// class; every record passes Check.
func TestEmit_V015Keys(t *testing.T) {
	login := func(claim string) Event {
		return Event{UserName: "example-user", ActorClass: ClassHuman, Action: "authn.login.oidc", Verb: "update", HTTPMethod: "PUT", StatusCode: 200,
			Outcome: OutcomeSuccess, Namespace: "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-user-clientconfig",
			Preview: PreviewFalse, RequestURI: "/oidc/login", SourceIPs: []string{"192.0.2.10"}, IdentityClaim: claim}
	}
	delegate := func(outcome, reason, audience string) Event {
		return Event{UserName: "example-agent", ActorClass: ClassService, OnBehalfOf: "example-user",
			Delegation: []Link{{Class: ClassService, Subject: "example-agent"}, {Class: ClassHuman, Subject: "example-user"}},
			Action:     "authn.delegate", Verb: "create", HTTPMethod: "POST", Outcome: outcome, DenialReason: reason,
			Namespace: "example-system", Group: "serviceaccount.authn.krateo.io", Version: "v1alpha1", Resource: "serviceaccounts", Subresource: "token",
			ObjectName: "example-agent", Preview: PreviewFalse, RequestURI: "/delegate", SourceIPs: []string{"192.0.2.10"}, TokenAudience: audience}
	}
	for _, tc := range []struct {
		name    string
		ev      Event
		key     string
		want    string // "" when the key must be absent
		noClass bool
	}{
		{"a claim", login(exampleClaims["oidc"]), KeyIdentityClaim, exampleClaims["oidc"], false},
		{"a malformed claim", login(`["oidc", "iss", "sub"]`), KeyIdentityClaim, "", false},
		{"an issued audience", delegate(OutcomeSuccess, "", "https://agentiko.example.com"), KeyTokenAudience, "https://agentiko.example.com", false},
		{"a refused audience", delegate(OutcomeDenied, DenialReasonAudienceNotAllowed, "other.example.com"), KeyTokenAudience, "other.example.com", false},
		{"a refused malformed audience", delegate(OutcomeDenied, DenialReasonAudienceNotAllowed, "Other Example"), KeyTokenAudience, "", false},
		{"a malformed audience is invalid_request, without it", delegate(OutcomeDenied, DenialReasonInvalidRequest, "https://agentiko.example.com/?x=1"), KeyTokenAudience, "", false},
		{"the public class", Event{UserName: "krateo:public", UserRoles: []string{"system:unauthenticated"}, ActorClass: ClassPublic,
			Action: "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201, Outcome: OutcomeSuccess,
			Namespace: "example-ns", Version: "v1", Resource: "configmaps", ObjectName: "example-cm", Preview: PreviewFalse,
			RequestURI: "/call", SourceIPs: []string{"192.0.2.10"}}, KeyActorClass, string(ClassPublic), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, rec := newEmitter(t, WithWriter(WriterRequest))
			e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), tc.ev)
			got := attrs(only(t, rec))
			v, here := got[tc.key]
			switch {
			case tc.want == "" && here:
				t.Errorf("%s = %q, want it omitted", tc.key, v.AsString())
			case tc.want != "" && (!here || v.AsString() != tc.want):
				t.Errorf("%s = %v, want %q", tc.key, v.Emit(), tc.want)
			}
			if inc, ok := got[KeyIncomplete]; ok {
				t.Errorf("incomplete = %q, want none", inc.AsString())
			}
			if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
				t.Errorf("Check: %v", vs)
			}
		})
	}
}

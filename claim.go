package audit

// ParseClaim maps authn's signed `principal` claim to a Class. Pass it the
// value plumbing's jwtutil reads (v1.34.0 or later), UserInfo.ActorPrincipal():
// the outermost actor's kind on a delegated token, else the token's own. The
// type parameter takes a jwtutil.Principal as it is, so this package does not
// import plumbing and stays OTel-only:
//
//	class, ok := audit.ParseClaim(ui.ActorPrincipal())
//
// ok is false for "" (a token minted before authn set the claim, or an actor
// with no kind) and for any value that is not one of the four classes, matched
// exactly. The caller then OMITS the class: never defaults it to human, and
// never fills it with the subject's kind. Emit marks the record
// krateo.audit.incomplete=actor_class.
func ParseClaim[P ~string](claim P) (Class, bool) {
	if c := Class(claim); c.Known() {
		return c, true
	}
	return "", false
}

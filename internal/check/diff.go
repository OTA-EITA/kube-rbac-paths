package check

// Diff keeps the findings of head that base does not have, compared by
// fingerprint, so a pull request is judged only on what it adds. The
// effective-admin summary is reduced the same way.
func Diff(base, head Result) Result {
	old := map[string]bool{}
	for _, f := range base.Findings {
		old[f.Fingerprint] = true
	}
	out := head
	out.Findings = nil
	for _, f := range head.Findings {
		if !old[f.Fingerprint] {
			out.Findings = append(out.Findings, f)
		}
	}
	out.Admins = nil
	for _, a := range head.Admins {
		if !old[fp(EffectiveAdmin, a.Subject.Key())] {
			out.Admins = append(out.Admins, a)
		}
	}
	return out
}

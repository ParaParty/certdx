package txcCertificateUpdater

func isSameStrSetIgnoringNil(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	return true
}

func derefAll(in []*string) ([]string, bool) {
	out := make([]string, len(in))
	for i, v := range in {
		if v == nil {
			return nil, false
		}
		out[i] = *v
	}
	return out, true
}

func isSameStrSetRejectNilItem(a []*string, b []string) bool {
	deref, ok := derefAll(a)
	if !ok {
		return false
	}
	return isSameStrSetIgnoringNil(deref, b)
}

func isSameStrSetRejectNilItemPtrArrPtrArr(a []*string, b []*string) bool {
	derefA, ok := derefAll(a)
	if !ok {
		return false
	}
	derefB, ok := derefAll(b)
	if !ok {
		return false
	}
	return isSameStrSetIgnoringNil(derefA, derefB)
}

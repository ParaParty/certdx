package txcCertificateUpdater

func isSameStrSetRejectNilItem(a []*string, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	setA := make(map[string]struct{}, len(a))
	for _, v := range a {
		if v == nil {
			return false
		}
		setA[*v] = struct{}{}
	}
	setB := make(map[string]struct{}, len(b))
	for _, v := range b {
		setB[v] = struct{}{}
	}

	for key := range setA {
		if _, ok := setB[key]; !ok {
			return false
		}
	}
	return true
}

func isSameStrSetRejectNilItemPtrArrPtrArr(a []*string, b []*string) bool {
	if len(a) != len(b) {
		return false
	}

	setA := make(map[string]struct{}, len(a))
	for _, v := range a {
		if v == nil {
			return false
		}
		setA[*v] = struct{}{}
	}
	setB := make(map[string]struct{}, len(b))
	for _, v := range b {
		if v == nil {
			return false
		}
		setB[*v] = struct{}{}
	}

	for key := range setA {
		if _, ok := setB[key]; !ok {
			return false
		}
	}
	return true
}

package txcCertificateUpdater

import "testing"

func ptr(s string) *string {
	return &s
}

func TestIsSameStrSetRejectNilItem(t *testing.T) {
	if !isSameStrSetRejectNilItem([]*string{ptr("b"), ptr("a")}, []string{"a", "b"}) {
		t.Fatal("expected equal sets with different order")
	}
	if isSameStrSetRejectNilItem([]*string{ptr("a"), ptr("b")}, []string{"a", "c"}) {
		t.Fatal("expected different sets")
	}
	if isSameStrSetRejectNilItem([]*string{ptr("a"), nil}, []string{"a", "b"}) {
		t.Fatal("expected nil item to reject")
	}
}

func TestIsSameStrSetRejectNilItemPtrArrPtrArr(t *testing.T) {
	if !isSameStrSetRejectNilItemPtrArrPtrArr([]*string{ptr("b"), ptr("a")}, []*string{ptr("a"), ptr("b")}) {
		t.Fatal("expected equal sets with different order")
	}
	if isSameStrSetRejectNilItemPtrArrPtrArr([]*string{ptr("a"), ptr("b")}, []*string{ptr("a"), ptr("c")}) {
		t.Fatal("expected different sets")
	}
	if isSameStrSetRejectNilItemPtrArrPtrArr([]*string{ptr("a"), ptr("b")}, []*string{ptr("a"), nil}) {
		t.Fatal("expected nil item to reject")
	}
}

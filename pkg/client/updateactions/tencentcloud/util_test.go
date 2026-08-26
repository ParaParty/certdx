package tencentcloud

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

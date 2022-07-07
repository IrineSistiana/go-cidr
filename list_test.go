package cidr

import (
	"bufio"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func Test_ListSort(t *testing.T) {
	in := `
0.0.0.0/25 # overlap
0.0.0.1/32 # overlap
0.0.0.0/24

0.1.0.0/23
0.0.2.0/24
0.0.1.0/24
`
	want := `
0.0.0.0/24
0.0.1.0/24
0.0.2.0/24
0.1.0.0/23
`

	l := NewList()
	for _, prefix := range loadPrefixes(t, strings.NewReader(in)) {
		l.Append(prefix)
	}
	l.Sort()

	wantPrefixes := loadPrefixes(t, strings.NewReader(want))
	if !reflect.DeepEqual(l.e, wantPrefixes) {
		t.Fatal()
	}
}

func Test_ListSortAndMerge(t *testing.T) {
	in := `
0.0.0.0/32
0.0.0.1/32
0.0.0.2/32
0.0.0.3/32
1.0.0.0/24
1.0.1.0/24
`
	want := `
0.0.0.0/30
1.0.0.0/23
`

	l := NewList()
	for _, prefix := range loadPrefixes(t, strings.NewReader(in)) {
		l.Append(prefix)
	}
	l.SortAndMerge()

	wantPrefixes := loadPrefixes(t, strings.NewReader(want))
	gotList := l.GetPrefixes()
	if !reflect.DeepEqual(gotList, wantPrefixes) {
		t.Fatalf("want %v, got %v", wantPrefixes, gotList)
	}
}

func Test_nextPrefixForMerge(t *testing.T) {
	tests := []struct {
		name     string
		p        string
		want     string
		wantZero bool
	}{
		{"v4 1", "0.0.0.0/32", "0.0.0.1/32", false},
		{"v4 1", "0.0.0.2/32", "0.0.0.3/32", false},
		{"v4 2", "::/1", "8000::/1", false},
		{"v4 tail", "1.0.0.1/32", "", true},
		{"v6 tail", "7000::/2", "", true},
		{"overflow1", "::/0", "", true},
		{"overflow2", "8000::/1", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := to6Prefix(netip.MustParsePrefix(tt.p))
			want := netip.Prefix{}
			if !tt.wantZero {
				want = to6Prefix(netip.MustParsePrefix(tt.want))
			}

			if got := nextPrefixForMerge(p); got != want {
				t.Errorf("nextPrefixForMerge() = %v, want %v", got, want)
			}
		})
	}
}

func Test_isZero(t *testing.T) {
	type args struct {
		v uint64
		b int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"0", args{0b1010101, 0}, false},
		{"1", args{0b1010101, 1}, true},
		{"2", args{0b1010101, 2}, false},
		{"3", args{0b1010101, 3}, true},
		{"63", args{0b1010101, 63}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isZero(tt.args.v, tt.args.b); got != tt.want {
				t.Errorf("isZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func loadPrefixes(t *testing.T, r io.Reader) []netip.Prefix {
	t.Helper()
	var ps []netip.Prefix
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s := scanner.Text()
		s, _, _ = strings.Cut(s, "#")
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			continue
		}
		ps = append(ps, to6Prefix(netip.MustParsePrefix(s)))
	}
	return ps
}

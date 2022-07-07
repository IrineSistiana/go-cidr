package cidr

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"net/netip"
	"sort"
)

var (
	ErrNotSorted   = errors.New("list is not sorted")
	ErrInvalidAddr = errors.New("addr is invalid")
)

// List is a list of netip.Prefix. It stores all netip.Prefix in one single slice
// and use binary search.
// It is suitable for large static cidr search.
// List converts IPv4 input netip.Prefix to IPv6 form. Therefore, all get functions that return
// netip.Prefix will always return a IPv6 form.
type List struct {
	// stores valid and masked ipv6 netip.Prefix(s)
	e      prefixList
	sorted bool
}

type prefixList []netip.Prefix

func (p prefixList) Len() int {
	return len(p)
}

func (p prefixList) Less(i, j int) bool {
	return p[i].Addr().Less(p[j].Addr())
}

func (p prefixList) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

// NewList creates a *List.
func NewList() *List {
	return &List{
		e: make([]netip.Prefix, 0),
	}
}

// Append appends new netip.Prefix to the list.
// This modified the list. Caller must call List.Sort() before calling List.Contains()
// If newPrefix is invalid, Append returns false.
func (list *List) Append(newPrefix netip.Prefix) bool {
	if !newPrefix.IsValid() {
		return false
	}
	newPrefix = to6Prefix(newPrefix)
	list.e = append(list.e, newPrefix)
	list.sorted = false
	return true
}

// Sort sorts the list and removes overlapped prefixes.
func (list *List) Sort() {
	list.sort(false)
}

// SortAndMerge sorts the list, removes overlapped prefixes, and merges
// continuous prefixes.
func (list *List) SortAndMerge() {
	list.sort(true)
}

func (list *List) sort(merge bool) {
	if list.sorted {
		return
	}

	sort.Sort(list.e)
	out := make([]netip.Prefix, 0)
	for i, p := range list.e {
		if i == 0 {
			out = append(out, p)
		} else {
			lvp := &out[len(out)-1]
			switch {
			case p.Addr() == lvp.Addr():
				if p.Bits() < lvp.Bits() {
					*lvp = p
				}
			case !lvp.Contains(p.Addr()):
				out = append(out, p)
				if merge {
					out = reverseMerge(out)
				}
			}
		}
	}

	list.e = out
	list.sorted = true
}

func reverseMerge(b []netip.Prefix) []netip.Prefix {
	for i := len(b) - 2; i >= 0; i-- {
		if nextPrefixForMerge(b[i]) == b[i+1] { // continuous cidr
			b[i] = netip.PrefixFrom(b[i].Addr(), b[i].Bits()-1)
			b = b[:i+1]
		} else {
			return b[:i+2]
		}
	}
	return b
}

// Contains reports whether the list includes the given netip.Addr.
// See also: GetPrefix.
func (list *List) Contains(addr netip.Addr) (bool, error) {
	p, err := list.GetPrefix(addr)
	return p.IsValid(), err
}

// GetPrefix get the netip.Prefix from list that includes the given netip.Addr.
// If list is not sorted or addr is not valid, an error will be returned.
// If no netip.Prefix was found, GetPrefix returns a zero netip.Prefix.
func (list *List) GetPrefix(addr netip.Addr) (netip.Prefix, error) {
	if !list.sorted {
		return netip.Prefix{}, ErrNotSorted
	}
	if !addr.IsValid() {
		return netip.Prefix{}, ErrInvalidAddr
	}

	addr = to6(addr)

	i, j := 0, len(list.e)
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		if list.e[h].Addr().Compare(addr) <= 0 {
			i = h + 1
		} else {
			j = h
		}
	}

	if i != 0 && list.e[i-1].Contains(addr) {
		return list.e[i-1], nil
	}

	return netip.Prefix{}, nil
}

// GetPrefixes returns a copy of list's inner []netip.Prefix.
func (list *List) GetPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list.e))
	out = append(out, list.e...)
	return out
}

func (list *List) Len() int {
	return len(list.e)
}

func (list *List) Cap() int {
	return cap(list.e)
}

func (list *List) Copy() *List {
	newList := &List{
		e: make(prefixList, 0, len(list.e)),
	}
	newList.e = append(newList.e, list.e...)
	return newList
}

// to6 returns an ipv6 netip.Addr. If addr is an ipv4, to6
// returns its v6-mapped form.
// addr must be valid.
func to6(addr netip.Addr) netip.Addr {
	if addr.Is6() {
		return addr
	}
	return netip.AddrFrom16(addr.As16())
}

// to6Prefix returns an ipv6 netip.Prefix . If p is an ipv4 prefix,
// to6Prefix returns its v6-mapped form.
// p must be valid.
func to6Prefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is6() {
		return p
	}
	return netip.PrefixFrom(to6(p.Addr()), p.Bits()+96)
}

func nextPrefixForMerge(p netip.Prefix) netip.Prefix {
	b16 := p.Addr().As16()
	hi := beUint64(b16[:8])
	lo := beUint64(b16[8:])

	b := 128 - p.Bits()
	var carry uint64
	if b < 64 {
		if !isZero(lo, b) {
			return netip.Prefix{}
		}
		lo, carry = bits.Add64(lo, 1<<b, 0)
		hi, carry = bits.Add64(hi, 0, carry)
	} else if b < 128 {
		if !isZero(hi, b-64) {
			return netip.Prefix{}
		}
		hi, carry = bits.Add64(hi, 1<<(b-64), 0)
	} else {
		return netip.Prefix{} // b is 128
	}

	if carry == 1 { // overflowed
		return netip.Prefix{}
	}

	putUint64(b16[:8], hi)
	putUint64(b16[8:], lo)
	return netip.PrefixFrom(netip.AddrFrom16(b16), p.Bits())
}

func beUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

func putUint64(b []byte, v uint64) {
	binary.BigEndian.PutUint64(b, v)
}

func isZero(v uint64, b int) bool {
	return v&(1<<b) == 0
}

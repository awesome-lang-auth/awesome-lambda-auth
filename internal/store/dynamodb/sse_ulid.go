package dynamodb

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"
)

// The ULID the SSE event log keys on (data-model.md §1.5): 48 bits of Unix
// milliseconds followed by 80 random bits, written as 26 characters of
// Crockford's base32. Two properties are the whole reason for the choice, and
// both are properties of the encoding rather than of any library:
//
//   - The string sorts as the number does. Base32 of a big-endian integer,
//     fixed width, over an alphabet in ascending byte order, is lexicographic
//     in exactly the order of the integer — so SK = E#<ulid> is a time-ordered
//     sort key and a cursor is a string comparison.
//   - The time half is readable back out. A replay horizon ("older than the
//     retention") and a truncation notice are decisions about a cursor's age,
//     and a ULID answers them without a read.
//
// It is written here rather than imported for the reason the rest of this
// package writes its own codecs (anyvalue.go): a module added for forty lines
// is a dependency in the go.mod of a deployed Lambda binary, and the two
// sibling blocks built beside this one edit go.mod as well.

// crockford is Crockford's base32 alphabet: the digits, then the letters
// without I, L, O and U. It is in ascending ASCII order, which is what makes
// the encoding order-preserving.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ulidLen is the encoded width: 128 bits in 5-bit groups, the first group
// carrying the top three bits alone.
const ulidLen = 26

// errNotAULID is what parseULID answers for anything that is not 26
// characters of the alphabet with a first character that fits in three bits.
var errNotAULID = errors.New("dynamodb: not a ULID")

// ulid is the 128-bit value, big-endian.
type ulid [16]byte

// ulidAt is the smallest ULID of a millisecond: its time half and a random
// half of zeros. It is the cursor for "from this instant", because every ULID
// minted in that millisecond or later sorts at or above it — and a Query for
// SK > E#<it> misses only the one value no generator here produces.
func ulidAt(t time.Time) ulid {
	var u ulid
	ms := uint64(t.UnixMilli())
	if t.UnixMilli() < 0 {
		ms = 0
	}
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	return u
}

// time is the ULID's millisecond, as UTC.
func (u ulid) time() time.Time {
	ms := uint64(u[0])<<40 | uint64(u[1])<<32 | uint64(u[2])<<24 |
		uint64(u[3])<<16 | uint64(u[4])<<8 | uint64(u[5])
	return time.UnixMilli(int64(ms)).UTC()
}

// String encodes the 128 bits, most significant group first.
func (u ulid) String() string {
	var out [ulidLen]byte
	// Walk the value five bits at a time from the least significant end: a
	// 128-bit shift register kept as two 64-bit halves.
	hi := uint64(u[0])<<56 | uint64(u[1])<<48 | uint64(u[2])<<40 | uint64(u[3])<<32 |
		uint64(u[4])<<24 | uint64(u[5])<<16 | uint64(u[6])<<8 | uint64(u[7])
	lo := uint64(u[8])<<56 | uint64(u[9])<<48 | uint64(u[10])<<40 | uint64(u[11])<<32 |
		uint64(u[12])<<24 | uint64(u[13])<<16 | uint64(u[14])<<8 | uint64(u[15])
	for i := ulidLen - 1; i >= 0; i-- {
		out[i] = crockford[lo&0x1f]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}

// parseULID decodes the canonical form. It accepts the upper-case alphabet
// only: this package mints every ULID it will ever be handed back, so a
// lower-case or an ambiguous-letter spelling (I, L, O) is not a client being
// liberal in what it sends but a value that did not come from here, and it is
// answered the way every unrecognised cursor is (docs/sse.md).
func parseULID(s string) (ulid, error) {
	var u ulid
	if len(s) != ulidLen {
		return u, fmt.Errorf("%w: %d characters, want %d", errNotAULID, len(s), ulidLen)
	}
	// The first character carries the top three bits alone; anything above
	// '7' would overflow 128 bits.
	if s[0] > '7' {
		return u, fmt.Errorf("%w: first character %q overflows 128 bits", errNotAULID, s[0])
	}
	var hi, lo uint64
	for i := 0; i < ulidLen; i++ {
		v := crockfordValue(s[i])
		if v < 0 {
			return u, fmt.Errorf("%w: %q is not in the alphabet", errNotAULID, s[i])
		}
		hi = hi<<5 | lo>>59
		lo = lo<<5 | uint64(v)
	}
	for i := 0; i < 8; i++ {
		u[i] = byte(hi >> (56 - 8*i))
		u[8+i] = byte(lo >> (56 - 8*i))
	}
	return u, nil
}

func crockfordValue(c byte) int {
	for i := 0; i < len(crockford); i++ {
		if crockford[i] == c {
			return i
		}
	}
	return -1
}

// ulidClock mints ULIDs that are strictly increasing within one process.
//
// The specification's monotonic mode: within one millisecond the random half
// is the previous one plus one, so two events a publisher raises in the same
// millisecond keep their order in the log — the property per-topic ordering
// rests on for a single publisher. A new millisecond draws fresh randomness,
// which is what keeps two processes minting in the same millisecond from
// colliding. A clock that steps backwards keeps the last millisecond rather
// than minting below it: an id that sorted before one already handed out
// would be invisible to every cursor past it.
type ulidClock struct {
	mu   sync.Mutex
	now  func() time.Time
	last ulid
}

func (c *ulidClock) next() (ulid, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	u := ulidAt(c.now())
	if u.time().Before(c.last.time()) || u.time().Equal(c.last.time()) {
		// Same (or an earlier) millisecond: increment the previous value's
		// random half, carrying through it.
		u = c.last
		for i := 15; i >= 6; i-- {
			u[i]++
			if u[i] != 0 {
				break
			}
			if i == 6 {
				// 2^80 ULIDs in one millisecond. Not reachable; refused
				// rather than wrapped, because a wrap would sort below the
				// ids already minted.
				return ulid{}, errors.New("dynamodb: ULID random half exhausted within one millisecond")
			}
		}
		c.last = u
		return u, nil
	}
	if _, err := rand.Read(u[6:]); err != nil {
		return ulid{}, fmt.Errorf("dynamodb: mint ULID: %w", err)
	}
	c.last = u
	return u, nil
}

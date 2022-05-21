package hdwsa

import (
	"errors"
	"testing"
)

// security parameters
var (
	qbits uint32 = 512
	rbits uint32 = 160
)

func BenchmarkG1(b *testing.B) {
	x := pp.pairing.NewZr().Rand() // pick a random number x
	// compute X = e(P, P)^x
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xP := pp.pairing.NewG1().PowZn(pp.P, x)
		pp.pairing.NewGT().Pair(pp.P, xP)
	}
}

func BenchmarkG2(b *testing.B) {
	x := pp.pairing.NewZr().Rand() // pick a random number x
	// compute X = e(P, P)^x
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PP := pp.pairing.NewGT().Pair(pp.P, pp.P)
		pp.pairing.NewGT().PowZn(PP, x)
		pp.pairing.NewG1().PowZn(pp.P, x)
	}
}

var errmsg = errors.New("bad signature")

// TestScheme is for testing the correctness of the scheme.
// run `go test -v -run TestScheme`
func TestScheme(t *testing.T) {
	pp := Setup(rbits, qbits)
	{
		// derive from level 0
		wsk0, wpk0 := pp.RootWalletKeyGen([]string{"id0"})
		dvk := pp.VerifyKeyDerive(rootID, &wpk0)
		if !pp.VerifyKeyCheck(dvk, rootID, wpk0, wsk0) {
			panic("VerifyKeyCheck wrong")
		}

		dsk := pp.SignKeyDerive(dvk, rootID, wpk0, wsk0)
		signature := pp.Sign(nil, dvk, dsk)
		if !pp.Verify(nil, signature, dvk) {
			panic(errmsg)
		}
	}

	{
		// derive from level 0, that is, obtain level 1
		wsk0, wpk0 := pp.RootWalletKeyGen(rootID)
		wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)
		dvk := pp.VerifyKeyDerive(level1, &wpk1)
		if !pp.VerifyKeyCheck(dvk, level1, wpk1, wsk1) {
			panic("VerifyKeyCheck wrong")
		}

		dsk := pp.SignKeyDerive(dvk, level1, wpk1, wsk1)
		signature := pp.Sign(nil, dvk, dsk)
		if !pp.Verify(nil, signature, dvk) {
			panic(errmsg)
		}
	}
}

var (
	rootID = []string{"id0"}
	level1 = []string{"id0", "id1"}
)

var pp *PublicParams = Setup(rbits, qbits)

func BenchmarkSchemeL0Setup(b *testing.B) {
	benchmarkSetup(b, rbits, qbits)
}

func BenchmarkSchemeL0RootWalletKeyGen(b *testing.B) {
	benchmarkRootWalletKenGen(b, pp)
}

#func BenchmarkSchemeL0VerifyKeyDerive(b *testing.B) { benchmarkLevel0VerifyKeyDerive(b, pp) }

#func BenchmarkSchemeL0VerifyKeyCheck(b *testing.B) { benchmarkLevel0VerifyKeyCheck(b, pp) }
#func BenchmarkSchemeL0SignKeyDerive(b *testing.B)  { benchmarkLevel0SignKeyDerive(b, pp) }
#func BenchmarkSchemeL0Sign(b *testing.B)           { benchmarkLevel0Sign(b, pp) }
#func BenchmarkSchemeL0Verify(b *testing.B)         { benchmarkLevel0Verify(b, pp) }

func BenchmarkSchemeL1WalletKeyDelegate(b *testing.B) { benchmarkLevel1WalletKeyDelegate(b, pp) }
func BenchmarkSchemeL1VerifyKeyDerive(b *testing.B)   { benchmarkLevel1VerifyKeyDerive(b, pp) }

func BenchmarkSchemeL1VerifyKeyCheck(b *testing.B) { benchmarkLevel1VerifyKeyCheck(b, pp) }
func BenchmarkSchemeL1SignKeyDerive(b *testing.B)  { benchmarkLevel1SignKeyDerive(b, pp) }
func BenchmarkSchemeL1Sign(b *testing.B)           { benchmarkLevel1Sign(b, pp) }
func BenchmarkSchemeL1Verify(b *testing.B)         { benchmarkLevel1Verify(b, pp) }

func benchmarkLevel0VerifyKeyDerive(b *testing.B, pp *PublicParams) {
	_, wpk0 := pp.RootWalletKeyGen(rootID)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.VerifyKeyDerive(rootID, &wpk0)
	}
}

func benchmarkLevel0VerifyKeyCheck(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	dvk := pp.VerifyKeyDerive(rootID, &wpk0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.VerifyKeyCheck(dvk, rootID, wpk0, wsk0)
	}
}

func benchmarkLevel0SignKeyDerive(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	dvk := pp.VerifyKeyDerive(rootID, &wpk0)
	if !pp.VerifyKeyCheck(dvk, rootID, wpk0, wsk0) {
		panic("error")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.SignKeyDerive(dvk, rootID, wpk0, wsk0)
	}
}

func benchmarkLevel0Sign(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	dvk := pp.VerifyKeyDerive(rootID, &wpk0)
	if !pp.VerifyKeyCheck(dvk, rootID, wpk0, wsk0) {
		panic("error")
	}

	dsk := pp.SignKeyDerive(dvk, rootID, wpk0, wsk0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.Sign(nil, dvk, dsk)
	}
}

func benchmarkLevel0Verify(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	dvk := pp.VerifyKeyDerive(rootID, &wpk0)
	if !pp.VerifyKeyCheck(dvk, rootID, wpk0, wsk0) {
		panic("error")
	}

	dsk := pp.SignKeyDerive(dvk, rootID, wpk0, wsk0)
	sig := pp.Sign(nil, dvk, dsk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.Verify(nil, sig, dvk)
	}
}

func benchmarkLevel1WalletKeyDelegate(b *testing.B, pp *PublicParams) {
	if pp == nil {
		panic("public params: nil")
	}
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.WalletKeyDelegate(level1, wpk0, wsk0)
	}
}

func benchmarkLevel1VerifyKeyDerive(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	wpk1, _ := pp.WalletKeyDelegate(level1, wpk0, wsk0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.VerifyKeyDerive(level1, &wpk1)
	}
}

func benchmarkLevel1VerifyKeyCheck(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)

	dvk := pp.VerifyKeyDerive(level1, &wpk1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.VerifyKeyCheck(dvk, level1, wpk1, wsk1)
	}
}

func benchmarkLevel1SignKeyDerive(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)

	dvk := pp.VerifyKeyDerive(level1, &wpk1)
	if !pp.VerifyKeyCheck(dvk, level1, wpk1, wsk1) {
		panic("error")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.SignKeyDerive(dvk, level1, wpk1, wsk1)
	}
}

func benchmarkLevel1Sign(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)

	dvk := pp.VerifyKeyDerive(level1, &wpk1)
	if !pp.VerifyKeyCheck(dvk, level1, wpk1, wsk1) {
		panic("error")
	}

	dsk := pp.SignKeyDerive(dvk, level1, wpk1, wsk1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.Sign(nil, dvk, dsk)
	}
}

func benchmarkLevel1Verify(b *testing.B, pp *PublicParams) {
	wsk0, wpk0 := pp.RootWalletKeyGen(rootID)

	wpk1, wsk1 := pp.WalletKeyDelegate(level1, wpk0, wsk0)

	dvk := pp.VerifyKeyDerive(level1, &wpk1)
	if !pp.VerifyKeyCheck(dvk, level1, wpk1, wsk1) {
		panic("error")
	}

	dsk := pp.SignKeyDerive(dvk, level1, wpk1, wsk1)
	sig := pp.Sign(nil, dvk, dsk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.Verify(nil, sig, dvk)
	}
}

func benchmarkSetup(b *testing.B, rbits uint32, qbits uint32) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Setup(rbits, qbits)
	}
}

func benchmarkRootWalletKenGen(b *testing.B, pp *PublicParams) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.RootWalletKeyGen(rootID)
	}
}

package hdwsa

import (
	"crypto/sha256"
	"github.com/Nik-U/pbc"
	"strings"
)

var hashFunc = sha256.New()

// domain separation tag
const (
	DSTForH0 = "hdwsa.h0"
	DSTForH1 = "hdwsa.h1"
	DSTForH2 = "hdwsa.h2"
	DSTForH3 = "hdwsa.h3"
	DSTForH4 = "hdwsa.h4"
)

func Setup(rbits, qbits uint32) *PublicParams {
	params := pbc.GenerateA(rbits, qbits)
	pairing := params.NewPairing()

	P := pairing.NewG1().Rand() // generator P for G1
	return &PublicParams{
		rbits:   rbits,
		qbits:   qbits,
		pairing: pairing,
		P:       P,
		PBytes:  P.Bytes(),
	}
}

func (pp *PublicParams) RootWalletKeyGen(ids []string) (WalletSecretKey, WalletPublicKey) {
	if len(ids) != 1 {
		panic("expect an identity")
	}

	var alpha, beta *pbc.Element // master secret key
REPEAT1:
	if alpha = pp.pairing.NewZr().Rand(); alpha.Is0() {
		goto REPEAT1
	}
REPEAT2:
	if beta = pp.pairing.NewZr().Rand(); beta.Is0() {
		goto REPEAT2
	}
	AID := pp.pairing.NewG1().PowZn(pp.P, alpha)
	BID := pp.pairing.NewG1().PowZn(pp.P, beta)
	return WalletSecretKey{
			alpha: alpha,
			beta:  beta,
			WalletPublicKey: WalletPublicKey{
				AID: AID,
				BID: BID,
			},
		},
		WalletPublicKey{
			AID: AID,
			BID: BID,
		}
}

func (pp *PublicParams) WalletKeyDelegate(idt []string, wpk WalletPublicKey, wsk WalletSecretKey) (WalletPublicKey, WalletSecretKey) {
	// compute QID
	Qid := pp.pairing.NewG1().SetFromStringHash(DSTForH0+strings.Join(idt, ""), hashFunc) // QID

	var alphaID, betaID *pbc.Element // Zp
REPEAT1:
	if alphaID = pp.pairing.NewZr().SetFromStringHash(DSTForH1+Qid.String()+pp.pairing.NewG1().PowZn(Qid, wsk.alpha).String(), hashFunc); alphaID.Is0() {
		goto REPEAT1
	}

REPEAT2:
	if betaID = pp.pairing.NewZr().SetFromStringHash(DSTForH2+Qid.String()+pp.pairing.NewG1().PowZn(Qid, wsk.beta).String(), hashFunc); betaID.Is0() {
		goto REPEAT2
	}

	AID := pp.pairing.NewG1().PowZn(pp.P, alphaID)
	BID := pp.pairing.NewG1().PowZn(pp.P, betaID)

	return WalletPublicKey{
			AID: AID,
			BID: BID,
		},
		WalletSecretKey{
			alpha: alphaID,
			beta:  betaID,
			WalletPublicKey: WalletPublicKey{
				AID: AID,
				BID: BID,
			},
		}
}

func (pp *PublicParams) VerifyKeyDerive(idt []string, wpk *WalletPublicKey) *DVK {
REPEAT:
	r := pp.pairing.NewZr().Rand() // pick a random r
        if r.Is0() {
		goto REPEAT
	}
	Qr := pp.pairing.NewG1().PowZn(pp.P, r) // Qr = rP

	qid := pp.pairing.NewG1().PowZn(wpk.BID, r) // rBID

	h3 := pp.pairing.NewG1().SetFromStringHash(DSTForH3+wpk.BID.String()+Qr.String()+qid.String(), hashFunc)

	return &DVK{Qr, pp.pairing.NewGT().Pair(h3, pp.pairing.NewG1().Neg(wpk.AID))}
}

func (pp *PublicParams) VerifyKeyCheck(dvk *DVK, ID []string, wpk WalletPublicKey, wsk WalletSecretKey) bool {
	h3 := pp.pairing.NewG1().SetFromStringHash(DSTForH3+wpk.BID.String()+dvk.Qr.String()+
		pp.pairing.NewG1().PowZn(dvk.Qr, wsk.beta).String(), hashFunc)

	pair := pp.pairing.NewGT().Pair(h3, pp.pairing.NewG1().Neg(wpk.AID))

	return dvk.Qvk.Equals(pair)
}

func (pp *PublicParams) SignKeyDerive(dvk *DVK, idt []string, wpk WalletPublicKey, wsvk WalletSecretKey) *DSK {
	Q1 := pp.pairing.NewG1().PowZn(dvk.Qr, wsvk.beta) // compute beta * Qr

	h3 := pp.pairing.NewG1().SetFromStringHash(DSTForH3+wpk.BID.String()+dvk.Qr.String()+Q1.String(), hashFunc) // compute H3(*, *, *)
	return &DSK{pp.pairing.NewG1().PowZn(h3, wsvk.alpha)}
}

func (pp *PublicParams) Sign(m []byte, dvk *DVK, dsk *DSK) *signature {
	// pick random x
REPEAT:
	x := pp.pairing.NewZr().Rand() // pick a random number x
        if x.Is0() {
		goto REPEAT
	}
	// compute X = e(P, P)^x
	xP := pp.pairing.NewG1().PowZn(pp.P, x)
	X := pp.pairing.NewGT().Pair(pp.P, xP)

	h := pp.pairing.NewZr().SetFromStringHash(DSTForH4+dvk.Qr.String()+dvk.Qvk.String()+string(m)+X.String(), hashFunc)

	// compute Qsigma
	Qsigma := pp.pairing.NewG1().PowZn(dsk.dsk, h)
	Qsigma.ThenAdd(xP)

	return &signature{h, Qsigma}
}

func (pp *PublicParams) Verify(m []byte, sigma *signature, dvk *DVK) bool {
	if sigma != nil || dvk != nil {
		// compute e(Qsigma, P)
		lsh := pp.pairing.NewGT().Pair(sigma.Qsigma, pp.P)

		// compute (Qvk)^h
		rsh := pp.pairing.NewGT().Mul(lsh, pp.pairing.NewGT().PowZn(dvk.Qvk, sigma.h))

		return sigma.h.Equals(pp.pairing.NewZr().SetFromStringHash(DSTForH4+dvk.Qr.String()+dvk.Qvk.String()+string(m)+rsh.String(), hashFunc))
	}
	return false
}

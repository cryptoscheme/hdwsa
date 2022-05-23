package hdwsa

import (
	"crypto/sha256"
	"strings"
	"github.com/Nik-U/pbc"
)

var hashFunc = sha256.New() // pbc.SetFromStringHash API will always reset hashFunc inner state before write.

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
REPEAT:
	P := pairing.NewG1().Rand() // generator P for G1
	if P.Is0() {
		goto REPEAT
	}
	return &PublicParams{
		rbits:   rbits,
		qbits:   qbits,
		pairing: pairing,
		P:       P,
		PBytes:  P.Bytes(),
	}
}

func (pp *PublicParams) RootWalletKeyGen(ids []string) (WalletSecretKey, WalletPublicKey) {
	var alpha, beta *pbc.Element // master secret key
REPEAT0:
	if alpha = pp.pairing.NewZr().Rand(); alpha.Is0() {
		goto REPEAT0
	}
	AIDC := make(chan *pbc.Element, 1)
	go func() {
		AIDC <- pp.pairing.NewG1().PowZn(pp.P, alpha)
		close(AIDC)
	}()

REPEAT1:
	if beta = pp.pairing.NewZr().Rand(); beta.Is0() {
		goto REPEAT1
	}

	BID := pp.pairing.NewG1().PowZn(pp.P, beta)
	AID := <-AIDC
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
REPEAT0:
	Qid := pp.pairing.NewG1().SetFromStringHash(DSTForH0+strings.Join(idt, ""), hashFunc) // QID
	if Qid.Is0() {
		goto REPEAT0
	}

	var alphaID, betaID *pbc.Element // Zp
REPEAT1:
	if alphaID = pp.pairing.NewZr().SetFromStringHash(DSTForH1+Qid.String()+pp.pairing.NewG1().PowZn(Qid, wsk.alpha).String(), hashFunc); alphaID.Is0() {
		goto REPEAT1
	}

	AIDC := make(chan *pbc.Element, 1)
	go func() {
		AIDC <- pp.pairing.NewG1().PowZn(pp.P, alphaID)
		close(AIDC)
	}()

REPEAT2:
	if betaID = pp.pairing.NewZr().SetFromStringHash(DSTForH2+Qid.String()+pp.pairing.NewG1().PowZn(Qid, wsk.beta).String(), hashFunc); betaID.Is0() {
		goto REPEAT2
	}

	BID := pp.pairing.NewG1().PowZn(pp.P, betaID)
	AID := <-AIDC
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
REPEAT0:
	r := pp.pairing.NewZr().Rand() // pick a random r
	if r.Is0() {
		goto REPEAT0
	}
	QrC := make(chan *pbc.Element, 1)
	go func() {
		QrC <- pp.pairing.NewG1().PowZn(pp.P, r) // Qr = rP
		close(QrC)
	}()

	qid := pp.pairing.NewG1().PowZn(wpk.BID, r) // rBID
	var build strings.Builder
	build.WriteString(DSTForH3)
	build.WriteString(wpk.BID.String())
	Qr := <-QrC
	build.WriteString(Qr.String())
	build.WriteString(qid.String())
REPEAT1:
	h3 := pp.pairing.NewG1().SetFromStringHash(build.String(), hashFunc)
	if h3.Is0() {
		goto REPEAT1
	}
	return &DVK{Qr, pp.pairing.NewGT().Pair(h3, pp.pairing.NewG1().Neg(wpk.AID))}
}

func (pp *PublicParams) VerifyKeyCheck(dvk *DVK, ID []string, wpk WalletPublicKey, wsk WalletSecretKey) bool {
	h3 := pp.pairing.NewG1().SetFromStringHash(DSTForH3+wpk.BID.String()+dvk.Qr.String()+
		pp.pairing.NewG1().PowZn(dvk.Qr, wsk.beta).String(), hashFunc)

	pair := pp.pairing.NewGT().Pair(h3, pp.pairing.NewG1().Neg(wpk.AID))

	return dvk.Qvk.Equals(pair)
}

func (pp *PublicParams) SignKeyDerive(dvk *DVK, idt []string, wpk WalletPublicKey, wsk WalletSecretKey) *DSK {
	Q1Ch := make(chan *pbc.Element, 1)
	go func(){
		Q1Ch <- pp.pairing.NewG1().PowZn(dvk.Qr, wsk.beta) // compute beta * Qr
		close(Q1Ch)
	}()

	var build strings.Builder
	build.WriteString(DSTForH3)
	build.WriteString(wpk.BID.String())
	build.WriteString(dvk.Qr.String())
	Q1 := <- Q1Ch
	build.WriteString(Q1.String())

	h3 := pp.pairing.NewG1().SetFromStringHash(build.String(), hashFunc) // compute H3(*, *, *)
	return &DSK{pp.pairing.NewG1().PowZn(h3, wsk.alpha)}
}

func (pp *PublicParams) Sign(m []byte, dvk *DVK, dsk *DSK) *signature {
	// pick random x
REPEAT0:
	x := pp.pairing.NewZr().Rand() // pick a random number x
	if x.Is0() {
		goto REPEAT0
	}
	xPCh := make(chan *pbc.Element, 1)
	// compute X = e(P, P)^x
	go func() {
		xPCh <- pp.pairing.NewG1().PowZn(pp.P, x)
		close(xPCh)
	}()

	PP := pp.pairing.NewGT().Pair(pp.P, pp.P)
	X := pp.pairing.NewGT().PowZn(PP, x)
REPEAT1:
	h4 := pp.pairing.NewZr().SetFromStringHash(DSTForH4+dvk.Qr.String()+dvk.Qvk.String()+string(m)+X.String(), hashFunc)
	if h4.Is0() {
		goto REPEAT1
	}

	// compute Qsigma
	Qsigma := pp.pairing.NewG1().PowZn(dsk.dsk, h4)
	Qsigma.ThenAdd(<-xPCh)

	return &signature{h4, Qsigma}
}

func (pp *PublicParams) Verify(m []byte, sigma *signature, dvk *DVK) bool {
	if sigma != nil || dvk != nil {
		// compute e(Qsigma, P)
		lshCh := make(chan *pbc.Element, 1)
		go func() {
			lshCh <- pp.pairing.NewGT().Pair(sigma.Qsigma, pp.P)
			close(lshCh)
		}()

		tem := pp.pairing.NewGT().PowZn(dvk.Qvk, sigma.h)
		gt := pp.pairing.NewGT()
		lsh := <-lshCh
		// compute (Qvk)^h
		rsh := gt.Mul(lsh, tem)
		z := pp.pairing.NewZr()

		return sigma.h.Equals(z.SetFromStringHash(DSTForH4+dvk.Qr.String()+dvk.Qvk.String()+string(m)+rsh.String(), hashFunc))
	}
	return false
}

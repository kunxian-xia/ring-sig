package ringsig

// Package ringsig implements AOS ring signature scheme[AOS02]

// References: 
// [AOS02] M. Abe, M. Ohkubo, K. Suzuki, 1-out-of-n signatures from a variety of keys, 
//         ASIACRYPT 2012, LNCS, Springer-Verlag, 2002, pp.415-432.

import (
	"strconv"
	"fmt"
	"io"
	"hash"
	"errors"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

var one = new(big.Int).SetInt64(1)

type RingSig struct {
	e []byte
	s []big.Int
}

type SignerOpts struct {
	h hash.Hash
	rand io.Reader
}

func mod(x, N int) int {
	if x < 0 {
		return x+N
	} else {
		return x
	}
}

//assume all public key are defined on the same curve
func Sign(pubs []ecdsa.PublicKey, j int, sk *ecdsa.PrivateKey, 
			msg []byte, opts *SignerOpts) *RingSig {
	curve := pubs[0].Curve
	sig := new(RingSig)
	N := len(pubs)
	es := make([][]byte, N)
	sig.s = make([]big.Int, N)

	if (j >= N || j < 0) {
		return nil
	}

	k, err := randFieldElement(curve, opts.rand)
	if err != nil {
		return nil
	}

	//e_{j+1} = e = H(k*G || m || P_{j+1})
	Kx, Ky := curve.ScalarBaseMult(k.Bytes())
	opts.h.Reset()
	opts.h.Write(Kx.Bytes())
	opts.h.Write(Ky.Bytes())
	opts.h.Write(msg)
	opts.h.Write(pubs[(j+1)%N].X.Bytes())
	opts.h.Write(pubs[(j+1)%N].Y.Bytes())
	e := opts.h.Sum(nil)
	es[(j+1)%N] = e

	//e_i = H(e_{i-1} * P_{i-1} + s_{i-1}*G || m || P_i)
	for i := (j+2)% N; i != (j+1)%N; i = (i+1)%N {
		s, err := randFieldElement(curve, opts.rand)
		if err != nil {
			return nil
		}
		//fmt.Println((i-1)%N)
		sig.s[mod(i-1, N)] = *s
		opts.h.Reset()
		Kx, Ky = curve.ScalarBaseMult(s.Bytes())
		Ex, Ey := curve.ScalarMult(pubs[mod(i-1, N)].X, pubs[mod(i-1, N)].Y, e)
		Kx, Ky = curve.Add(Kx, Ky, Ex, Ey)
		opts.h.Write(Kx.Bytes())
		opts.h.Write(Ky.Bytes())
		opts.h.Write(msg)
		opts.h.Write(pubs[i].X.Bytes())
		opts.h.Write(pubs[i].Y.Bytes())
		e = opts.h.Sum(nil)
		es[i] = e
	}
	E := new(big.Int).SetBytes(e)
	//s_j = (k - e_j * sk.D)% curve.N
	s := k.Sub(k, E.Mul(E, sk.D))
	sig.s[j] = *(E.Mod(s, curve.Params().N))
	sig.e = es[0]

	return sig
}

func Verify(pubs []ecdsa.PublicKey, sig *RingSig, msg []byte, opts *SignerOpts) (bool, error) {
	if len(pubs) != len(sig.s) {
		return false,  errors.New("公钥数量不等于签名数")
	}
	N := len(pubs)
	e0 := sig.e
	e1 := e0
	for i := 1; i <= N; i++ {
		Px, Py := pubs[i-1].ScalarMult(pubs[i-1].X, pubs[i-1].Y, e1)
		Qx, Qy := pubs[i-1].ScalarBaseMult(sig.s[i-1].Bytes())
		Px, Py = pubs[i-1].Add(Px, Py, Qx, Qy)
		opts.h.Reset()
		opts.h.Write(Px.Bytes())
		opts.h.Write(Py.Bytes())
		opts.h.Write(msg)
		opts.h.Write(pubs[i%N].X.Bytes())
		opts.h.Write(pubs[i%N].Y.Bytes())
		e1 = opts.h.Sum(nil)
	}
	//at last, test if e1 == e0?
	flag := true
	for i := 0; i < len(e0); i++ {
		if e0[i] != e1[i] {
			flag = false
			break
		}
	}
	if flag == true {
		return true, nil
	} else {
		return false, errors.New("非法签名")
	}
}

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	fmt.Println("nonce has "+ strconv.Itoa(len(b)) + " bytes")
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}
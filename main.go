package main

import (
	"crypto/elliptic"
	"math/big"
	"fmt"
	"github.com/gtank/cryptopasta"
	"log"
	"crypto/ecdsa"
	"crypto/sha256"
)

func ecRecovery(data []byte, rawSign []byte) (ecdsa.PublicKey,ecdsa.PublicKey) {
	r := big.Int{}
	s := big.Int{}
	sigLen := len(rawSign)
	r.SetBytes(rawSign[:(sigLen / 2)])
	s.SetBytes(rawSign[(sigLen / 2):])

	expy := new(big.Int).Sub(elliptic.P256().Params().N,big.NewInt(2))
	rinv := new(big.Int).Exp(&r,expy ,elliptic.P256().Params().N)
	z := new(big.Int).SetBytes(data)

	tmp1 := new(big.Int).Mul(&r,&r)
	tmp1.Mul(tmp1,&r)

	tmp2 := new(big.Int).Mul(big.NewInt(3),&r)

	tmp4 := new(big.Int).Sub(tmp1,tmp2)
	tmp4.Add(tmp4,elliptic.P256().Params().B)

	//y_squard := new(big.Int).Mod(tmp4,elliptic.P256().Params().P)

	y1 := new(big.Int).ModSqrt(tmp4,elliptic.P256().Params().P)
	y2 := new(big.Int).Neg(y1)
	y2.Mod(y2,elliptic.P256().Params().P)

	p1, p2 := elliptic.P256().ScalarMult(&r,y1,s.Bytes())
	p3, p4 := elliptic.P256().ScalarBaseMult(z.Bytes())

	p5 := new(big.Int).Neg(p4)
	p5.Mod(p5,elliptic.P256().Params().P)

	q1, q2 := elliptic.P256().Add(p1,p2,p3,p5)
	q3, q4 := elliptic.P256().ScalarMult(q1,q2,rinv.Bytes())

	n1, n2 := elliptic.P256().ScalarMult(&r,y2,s.Bytes())
	n3, n4 := elliptic.P256().ScalarBaseMult(z.Bytes())

	n5 := new(big.Int).Neg(n4)
	n5.Mod(n5,elliptic.P256().Params().P)

	q5, q6 := elliptic.P256().Add(n1,n2,n3,n5)
	q7, q8 := elliptic.P256().ScalarMult(q5,q6,rinv.Bytes())

	key1 := ecdsa.PublicKey{Curve:elliptic.P256(),X:q3,Y:q4}
	key2 := ecdsa.PublicKey{Curve:elliptic.P256(),X:q7,Y:q8}
	return key1,key2
}

func comparePublicKey(key1, key2 ecdsa.PublicKey) bool {
	x := key1.X.Cmp(key2.X)
	y := key2.Y.Cmp(key2.Y)
	if x == 0 && y == 0 {
		return true
	} else {
		return false
	}
}

func testEcRecovery() {
	fmt.Println("--------------")
	key, err := cryptopasta.NewSigningKey()
	if err != nil {
		log.Fatal(err)
	}

	data := []byte("hello world.")
	sign, err := cryptopasta.Sign(data,key)
	if err != nil {
		log.Fatal(err)
	}

	result := cryptopasta.Verify(data,sign,&key.PublicKey)
	if result == false {
		log.Fatal("verify failed.")
	}

	hash := sha256.Sum256(data)

	key1,key2 := ecRecovery(hash[:],sign)
	if comparePublicKey(key.PublicKey,key1) || comparePublicKey(key.PublicKey,key2) {
		fmt.Println("match found.")
	} else {
		log.Fatal("match not found!!!")
	}
}

func main() {
	for i := 1; i< 1000000 ; i++ {
		testEcRecovery()
		fmt.Println(i)
	}
}

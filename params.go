package kem

import (
	"errors"
)

const (
	KYBER_N   = 256
	KYBER_Q   = 7681
	KYBER_ETA = 2

	// size in byte of hashes and seeds
	KYBER_SYMBYTES = 32
	// size in bytes of shared key
	KYBER_SSBYTES = 32

	KYBER_POLYBYTES = 384
)

func polySizes(k int) (map[string]int, error) {
	r := map[string]int{}
	compr := "POLY_COMPRESSED_BYTES"
	vec_compr := "POLY_VEC_COMPRESSED_BYTES"
	vec := "POLY_VEC_BYTES"

	switch k {
	case 2:
		r[compr] = 96
		r[vec_compr] = k * 320
	case 3:
		r[compr] = 128
		r[vec_compr] = k * 320
	case 4:
		r[compr] = 160
		r[vec_compr] = k * 352
	default:
		return r, errors.New("k invalid. Must be 2, 3 or 4")
	}
	r[vec] = k * KYBER_POLYBYTES
	return r, nil
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"gitlab.kudelski.com/ks-fun/go-pqs/crystals-kyber/utils"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NoisePublicKeySize  = 32
	NoisePrivateKeySize = 32
)

type (
	//NoisePublicKey    [NoisePublicKeySize]byte
	//NoisePrivateKey   [NoisePrivateKeySize]byte
	NoiseSymmetricKey [chacha20poly1305.KeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes

	KyberPKEPK [utils.SIZEPKPKE]byte
	KyberPKESK [utils.SIZESKPKE]byte

	KyberKEMPK [utils.SIZEPK]byte
	KyberKEMSK [utils.SIZESK]byte
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

// NEED FOR TO/FROM HEX??

func (key KyberKEMSK) IsZero() bool {
	var zero KyberKEMSK
	return key.Equals(zero)
}

func (key KyberKEMSK) Equals(tar KyberKEMSK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

/**
func (key *NoisePrivateKey) FromHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	key.clamp()
	return
}

func (key *NoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	if key.IsZero() {
		return
	}
	key.clamp()
	return
}

func (key NoisePrivateKey) ToHex() string {
	return hex.EncodeToString(key[:])
}

func (key *NoisePublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

**/
//transforms a key to hex
func (key []byte) ToHex() string {
	return hex.EncodeToString(key[:])
}

func (key KyberKEMPK) IsZero() bool {
	var zero KyberKEMPK
	return key.Equals(zero)
}

func (key KyberKEMPK) Equals(tar KyberKEMPK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoiseSymmetricKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoiseSymmetricKey) ToHex() string {
	return hex.EncodeToString(key[:])
}

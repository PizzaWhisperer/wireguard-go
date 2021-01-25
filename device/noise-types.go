/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"

	utils "gitlab.kudelski.com/ks-fun/go-pqs/crystals-kyber/utils"
	"golang.org/x/crypto/chacha20poly1305"
)

type (
	NoiseSymmetricKey [chacha20poly1305.KeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes

	KyberPKEPK [utils.SIZEPK]byte
	KyberPKESK [utils.SIZEPKESK]byte

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

func (key KyberKEMSK) IsZero() bool {
	var zero KyberKEMSK
	return key.Equals(zero)
}

func (key KyberKEMSK) Equals(tar KyberKEMSK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func KeyToHex(key []byte) string {
	return hex.EncodeToString(key[:])
}

func (key KyberKEMSK) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key KyberKEMPK) FromHex(src string) error {
	return loadExactHex(key[:], src)
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

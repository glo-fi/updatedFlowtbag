/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Package cryptopan implements the Crypto-PAn prefix-preserving IP address
// sanitization algorithm as specified by J. Fan, J. Xu, M. Ammar, and S. Moon.
//
// Crypto-PAn has the following properties:
//
//  * One-to-one - The mapping from original IP addresses to anonymized IP
//    addresses is one-to-one.
//
//  * Prefix-preserving - In Crypto-PAn, the IP address anonymization is
//    prefix-preserving. That is, if two original IP addresses share a k-bit
//    prefix, their anonymized mappings will also share a k-bit prefix.
//
//  * Consistent across traces - Crypto-PAn allows multiple traces to be
//    sanitized in a consistent way, over time and across locations.  That is,
//    the same IP address in different traces is anonymized to the same
//    address, even though the traces might be sanitized separately at
//    different time and/or at different locations.
//
//  * Cryptography-based - To sanitize traces, trace owners provide Crypto-PAn
//    a secret key.  Anonymization consistency across multiple traces is
//    achieved by the use of the same key.  The construction of Crypto-PAn
//    preserves the secrecy of the key and the (pseudo)randomness of the
//    mapping from an original IP address to its anonymized counterpart.
//
// As an experimental extension, anonymizing IPv6 addresses is also somewhat
// supported, but is untested beyond a cursory examination of the output.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"net"
	"strconv"
)

const (
	Size = keySize + blockSize

	blockSize = aes.BlockSize
	keySize   = 128 / 8
)

var ipMap = make(map[string]string)

type keySizeError int

func (e keySizeError) Error() string {
	return "invalid key size " + strconv.Itoa(int(e))
}

type bitvector [blockSize]byte

func (v *bitvector) SetBit(idx, bit uint) {
	byteIdx := idx / 8
	bitIdx := 7 - idx&7
	oldBit := uint8((v[byteIdx] & (1 << bitIdx)) >> bitIdx)
	flip := 1 ^ subtle.ConstantTimeByteEq(oldBit, uint8(bit))
	v[byteIdx] ^= byte(flip << bitIdx)
}

func (v *bitvector) Bit(idx uint) uint {
	byteIdx := idx / 8
	bitIdx := 7 - idx&7
	return uint((v[byteIdx] & (1 << bitIdx)) >> bitIdx)
}

type Cryptopan struct {
	aesImpl cipher.Block
	pad     bitvector
}

func (ctx *Cryptopan) Anonymize(addr net.IP) net.IP {
	var obfsAddr []byte
	if v4addr := addr.To4(); v4addr != nil {
		obfsAddr = ctx.anonymize(v4addr)
		return net.IPv4(obfsAddr[0], obfsAddr[1], obfsAddr[2], obfsAddr[3])
	} else if v6addr := addr.To16(); v6addr != nil {
		// None of the other implementations in the wild do something like
		// this, but there's no reason I can think of beyond "it'll be really
		// slow" as to why it's not valid.
		obfsAddr = ctx.anonymize(v6addr)
		addr := make(net.IP, net.IPv6len)
		copy(addr[:], obfsAddr[:])
		return addr
	}

	panic("unsupported address type")
}

func (ctx *Cryptopan) anonymize(addr net.IP) []byte {
	addrBits := uint(len(addr) * 8)
	var origAddr, input, output, toXor bitvector
	copy(origAddr[:], addr[:])
	copy(input[:], ctx.pad[:])

	// The first bit does not take any bits from orig_addr.
	ctx.aesImpl.Encrypt(output[:], input[:])
	toXor.SetBit(0, output.Bit(0))

	// The rest of the one time pad is build by copying orig_addr into the AES
	// input bit by bit (MSB first) and encrypting with ECB-AES128.
	for pos := uint(1); pos < addrBits; pos++ {
		// Copy an additional bit into input from orig_addr.
		input.SetBit(pos-1, origAddr.Bit(pos-1))

		// ECB-AES128 the input, only one bit of output is used per iteration.
		ctx.aesImpl.Encrypt(output[:], input[:])

		// Note: Per David Stott@Lucent, using the MSB of the PRF output leads
		// to weaker anonymized output.  Jinliang Fan (one of the original
		// Crypto-PAn authors) claims that a new version that incorporates one
		// of his suggested tweaks is forthcoming, but it looks like that never
		// happened, and no one else does that.
		//
		// Something like: toXor.SetBit(pos, output.Bit(pos)) will fix this,
		// but will lead to different output than every other implementation.
		toXor.SetBit(pos, output.Bit(0))
	}

	// Xor the pseudorandom one-time-pad with the address and return.
	for i := 0; i < len(addr); i++ {
		toXor[i] ^= origAddr[i]
	}
	return toXor[:len(addr)]
}

// New constructs and initializes Crypto-PAn with a given key.
func New(key []byte) (ctx *Cryptopan, err error) {
	if len(key) != Size {
		return nil, keySizeError(len(key))
	}

	ctx = new(Cryptopan)
	if ctx.aesImpl, err = aes.NewCipher(key[0:keySize]); err != nil {
		return nil, err
	}
	ctx.aesImpl.Encrypt(ctx.pad[:], key[keySize:])
	return
}

func (ctx *Cryptopan) StringAnonymise(input string) (output string) {
	parsed := net.ParseIP(input)
	anon_addr := ctx.Anonymize(parsed)
	return anon_addr.String()
}

func (ctx *Cryptopan) QueryCryptoPanMap(input string) (output string) {
	output, ok := ipMap[input]
	if ok {
		return output
	} else {
		output := ctx.StringAnonymise(input)
		ipMap[input] = output
		return output
	}
}

func (ctx *Cryptopan) AnonymiseFlow(flow *Flow) *Flow {
	srcip := ctx.QueryCryptoPanMap(flow.srcip)
	dstip := ctx.QueryCryptoPanMap(flow.dstip)

	flow.srcip = srcip
	flow.dstip = dstip

	return flow
}

func randomKey() []byte {
	b := make([]byte, Size)
	rand.Read(b)
	return b
}

#!/usr/bin/env bats

load common

@test "aes-gcm: Encrypt" {
	run $CHECK encrypt aes-gcm \
		-k "787878783132384269744b6579787878" \
		-I "787878393642697449567878" \
		-i "536f6d654e696365506c61696e74657874"
	echo "$output"
	[ $status -eq 0 ]
	[ "$(digest)" = "439195d4a7c4b4419cd9738b893753aec52900a6d0b6952c1e02e2724a1481066a" ]
}
@test "aes-gcm: Decrypt" {
	run $CHECK decrypt aes-gcm \
		-k "787878783132384269744b6579787878" \
		-I "787878393642697449567878" \
		-i "439195d4a7c4b4419cd9738b893753aec52900a6d0b6952c1e02e2724a1481066a"
	[ $status -eq 0 ]
	[ "$(digest)" = "536f6d654e696365506c61696e74657874" ]
}
@test "aes-gcm: Decrypt manipulated ciphertext" {
	run $CHECK decrypt aes-gcm \
		-k "787878783132384269744b6579787878" \
		-I "787878393642697449567878" \
		-i "439196d4a7c4b4419cd9738b893753aec52900a6d0b6952c1e02e2724a1481066a"
	[ $status -eq 1 ]
	echo "$output" | grep -q "more-ciphers: aes-gcm: Could not decrypt: security library: received bad data."
}
@test "aes-gcm: Encrypt with 32 Bit tag length" {
	run $CHECK encrypt aes-gcm \
		-k "787878783132384269744b6579787878" \
		-I "787878393642697449567878" \
		-i "536f6d654e696365506c61696e74657874" \
		-t 4
	echo "$output"
	[ $status -eq 0 ]
	[ "$(digest)" = "439195d4a7c4b4419cd9738b893753aec52900a6d0" ]
}
@test "aes-gcm: Decrypt with 32 Bit tag length" {
	run $CHECK decrypt aes-gcm \
		-k "787878783132384269744b6579787878" \
		-I "787878393642697449567878" \
		-i "439195d4a7c4b4419cd9738b893753aec52900a6d0" \
		-t 4
	echo "$output"
	[ $status -eq 0 ]
	[ "$(digest)" = "536f6d654e696365506c61696e74657874" ]
}

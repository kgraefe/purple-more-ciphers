#!/usr/bin/env bats

load common

@test "random" {
	# There not so much we can test here other then that it returns "something"
	# of the expected size and that it changes from call to call.
	#
	# The expected size is 4096 Byte (8192 hex characters). This is an
	# implementation detail of the ciphertest executable since this algorithm
	# just fills the given buffer completely with random data.

	run $CHECK hash random
	echo "$output"
	[ $status -eq 0 ]
	[ $(digest | wc -c) -eq 8192 ]
	r1=$(digest)

	run $CHECK hash random
	[ $status -eq 0 ]
	[ $(digest | wc -c) -eq 8192 ]
	r2=$(digest)

	[ "$r1" != "$r2" ]
}

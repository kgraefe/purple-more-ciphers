#!/usr/bin/env bats

load common

@test "argon2i: Basic digest" {
	# echo -n "password" | xxd -p => 70617373776f7264
	# echo -n "somesalt" | xxd -p => 736f6d6573616c74
	run $CHECK hash argon2i -i "70617373776f7264" -s "736f6d6573616c74"
	[ $status -eq 0 ]
	[ "$(digest)" = "896874eaf0fc172dbbc1ff67a67e855d68825f82baa56e947b5067cf3d3b67c0" ]
}
@test "argon2d: Basic digest" {
	run $CHECK hash argon2d -i "70617373776f7264" -s "736f6d6573616c74"
	[ $status -eq 0 ]
	[ "$(digest)" = "dbe242a10b58ff6c79174541f691153f7c41360b963f54f6e548b43ed66e93ca" ]
}
@test "argon2id: Basic digest" {
	run $CHECK hash argon2id -i "70617373776f7264" -s "736f6d6573616c74"
	[ $status -eq 0 ]
	[ "$(digest)" = "a8b9a5e5c6ea1403ba63154786b4811cfd1459dc6b23190d70cf1a317ddb9735" ]
}

@test "argon2i: No salt" {
	run $CHECK hash argon2i -i "70617373776f7264"
	[ $status -eq 1 ]
	echo "$output" | grep -q "more-ciphers: Could not get argon2 digest: Salt is too short"
}
@test "argon2i: 48 bit hash" {
	run $CHECK hash argon2i \
		-i "70617373776f7264" -s "736f6d6573616c74" -o "outlen=48"
	[ $status -eq 0 ]
	[ "$(digest)" = "d93fa9c332f3a8c9ca39d5110631ed8c823d0060be10429937b31d28cceb7af45e65e39595155e056a943cbcb733e11d" ]
}
@test "argon2i: time cost 10x" {
	run $CHECK hash argon2i \
		-i "70617373776f7264" -s "736f6d6573616c74" -o "time-cost=10"
	[ $status -eq 0 ]
	[ "$(digest)" = "dc77114716aadabfe9f61b40c445458ee15f36ca1871456fd1fd7ab766ffb9fb" ]
}
@test "argon2i: memory cost 64 MiB" {
	run $CHECK hash argon2i \
		-i "70617373776f7264" -s "736f6d6573616c74" -o "memory-cost=65536"
	[ $status -eq 0 ]
	[ "$(digest)" = "ef4d63a9797b79d0bacd5a461f6e0e223b1256e273e0bbb7891d5dc7c29392f2" ]
}
@test "argon2i: parallelism of 4" {
	run $CHECK hash argon2i \
		-i "70617373776f7264" -s "736f6d6573616c74" -o "lanes=4" -o "threads=4"
	[ $status -eq 0 ]
	[ "$(digest)" = "4da076fa995c7819689326ed7879a33493cd2810d889754cb0dcecaa7466671e" ]
}

@test "argon2id: sane parameters (time=5x, mem=128MiB, parallelism=4)" {
	run $CHECK hash argon2id \
		-i "70617373776f7264" -s "736f6d6573616c74" \
		-o "time-cost=5" -o "memory-cost=131072" -o "lanes=4" -o "threads=4"
	[ $status -eq 0 ]
	[ "$(digest)" = "86723cddfae1435bfa9ee9256a3968bd3bf1e614054e7801651fba321e7b2c39" ]
}

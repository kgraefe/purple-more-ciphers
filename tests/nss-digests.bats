#!/usr/bin/env bats

load common

@test "nss: sha384" {
	run $CHECK hash sha384 -i "70617373776f7264"
	[ $status -eq 0 ]
	[ "$(digest)" = "a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7" ]
}
@test "nss: sha512" {
	run $CHECK hash sha512 -i "70617373776f7264"
	[ $status -eq 0 ]
	[ "$(digest)" = "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86" ]
}

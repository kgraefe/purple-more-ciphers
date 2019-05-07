#!/usr/bin/env bats

CHECK="${CHECK:-./tests/check}"

# The check executable uses libpurple and glib which both need even more
# libraries. On Windows those are not installed globally so we try to borrow
# them from an existing Pidgin installation.
if [[ $OSTYPE == cygwin* ]]; then
	if [ -z "$PIDGINPATH" ]; then
		PIDGINPATH="$(
			cygpath -f /proc/registry32/HKEY_LOCAL_MACHINE/SOFTWARE/pidgin/@
		)"
	fi
	export PATH="$PIDGINPATH:$PIDGINPATH/Gtk/bin:$PATH"
fi

digest() {
	echo "$output" | awk 'BEGIN {RS="\r\n|\n"} /test: Digest:/ {$4=$4; printf "%s",$4}'
}

@test "argon2i: Basic digest" {
	run $CHECK -c argon2i -a hash -p "password" -s "somesalt"
	[ $status -eq 0 ]
	[ "$(digest)" = "896874eaf0fc172dbbc1ff67a67e855d68825f82baa56e947b5067cf3d3b67c0" ]
}
@test "argon2d: Basic digest" {
	run $CHECK -c argon2d -a hash -p "password" -s "somesalt"
	[ $status -eq 0 ]
	[ "$(digest)" = "dbe242a10b58ff6c79174541f691153f7c41360b963f54f6e548b43ed66e93ca" ]
}
@test "argon2id: Basic digest" {
	run $CHECK -c argon2id -a hash -p "password" -s "somesalt"
	[ $status -eq 0 ]
	[ "$(digest)" = "a8b9a5e5c6ea1403ba63154786b4811cfd1459dc6b23190d70cf1a317ddb9735" ]
}

@test "argon2i: No salt" {
	run $CHECK -c argon2i -a hash -p "password"
	[ $status -eq 1 ]
	echo "$output" | grep -q "more-ciphers: Could not get argon2 digest: Salt is too short"
}

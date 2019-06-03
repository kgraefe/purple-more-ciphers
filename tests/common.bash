CHECK="${CHECK:-$BATS_TEST_DIRNAME/ciphertest}"

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

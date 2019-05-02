#!/bin/bash

set -eo pipefail

test -f configure.ac.in
VERSION=$(./scripts/gen-version.sh)

sed \
	-e "s/@@VERSION@@/$VERSION/" \
configure.ac.in >configure.ac

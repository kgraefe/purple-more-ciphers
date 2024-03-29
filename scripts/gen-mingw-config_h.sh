#!/bin/bash

set -eo pipefail

test -f configure.ac

PLUGIN_AUTHOR="$(awk -F\" '/PLUGIN_AUTHOR/ {print $2}' configure.ac)"
PLUGIN_ID="$(awk -F\" '/PLUGIN_ID/ {print $2}' configure.ac)"
PLUGIN_STATIC_NAME="$(awk -F\" '/PLUGIN_STATIC_NAME/ {print $2}' configure.ac)"
PLUGIN_WEBSITE="$(awk -F\" '/PLUGIN_WEBSITE/ {print $2}' configure.ac)"
PLUGIN_PREFS_PREFIX="$(awk -F\" '/PLUGIN_PREFS_PREFIX/ {print $2}' configure.ac)"
PLUGIN_VERSION=$(./scripts/gen-version.sh)

cat << EOF
/* Generated by scripts/gen_mingw_config_h.sh
 * from files VERSION and configure.ac.
 */
#define PLUGIN_AUTHOR "$PLUGIN_AUTHOR"
#define PLUGIN_ID "$PLUGIN_ID"
#define PLUGIN_STATIC_NAME "$PLUGIN_STATIC_NAME"
#define PLUGIN_VERSION "$PLUGIN_VERSION"
#define PLUGIN_WEBSITE "$PLUGIN_WEBSITE"
#define PLUGIN_PREFS_PREFIX "$PLUGIN_PREFS_PREFIX"
EOF

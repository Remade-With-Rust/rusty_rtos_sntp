#!/bin/sh
# Generate the C arm of K7's coreSNTP serializer differential.
#
# `core_sntp_serializer.c` is compiled VERBATIM out of the pinned checkout in
# the umbrella; this script never copies or edits it. Fetch it first with
#
#     cargo run --manifest-path tools/kairos/Cargo.toml -- oracle fetch --lib coreSNTP
#
# The trace it writes is checked in, so the Rust side diffs it in CI with no C
# toolchain -- the same arrangement the kernel corpus, the heap differentials,
# backoff and json all use.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
lib="$here/../../oracle/coreSNTP"
src="$lib/source/core_sntp_serializer.c"

[ -f "$src" ] || { echo "no core_sntp_serializer.c at $src -- run \`kairos oracle fetch --lib coreSNTP\` first" >&2; exit 1; }

# SNTP_DO_NOT_USE_CUSTOM_CONFIG is the library own switch for building without
# an application config header. It selects the SHIPPED defaults rather than
# replacing anything, so the C under test is still stock.
cc -O2 -g -Wall -Wextra -DSNTP_DO_NOT_USE_CUSTOM_CONFIG \
   -I "$lib/source/include" \
   -o "$here/sntp_driver" \
   "$src" "$here/sntp_driver.c"

"$here/sntp_driver" > "$here/sntp.trace"
echo "wrote $(wc -l < "$here/sntp.trace") lines to $here/sntp.trace"

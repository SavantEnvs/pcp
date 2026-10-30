#!/usr/bin/env bash
#
# mayhem/build.sh — build pcp's fuzz harnesses (sanitized libpcp) and upstream's cmocka unit tests
# (normal flags). pcp only supports in-tree autotools builds, so the tree is cleaned and reconfigured
# between the two builds. Everything resolves from the image (apt packages); no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
# Artifacts live in a directory that mayhem/.gitignore ignores (the root .gitignore is upstream's).
OUT="$SRC/mayhem/out"
mkdir -p "$OUT"

CONF=(--without-qt --without-python3 --without-perl --without-systemd --without-selinux
      --without-infiniband --without-pmdabpf --without-pmdabpftrace --without-x
      --with-secure-sockets=no)
LIBS_SYS="-llzma -lm -lpthread -ldl"

# Drop every object/generated file of the directories we build, so the two configurations never mix.
pcp_clean() {
    [ -f src/include/builddefs ] || return 0
    make -C src/libpcp clean >/dev/null 2>&1 || true
    make -C src/pmlc clean >/dev/null 2>&1 || true
}

# 1) Upstream's own unit tests (qa/src/test_*.c, cmocka), NORMAL flags, linked statically so the
#    later sanitized build cannot disturb them.
pcp_clean
env -u CFLAGS -u LDFLAGS -u CXXFLAGS ./configure CC="$CC" "${CONF[@]}" >/dev/null
make -C src/include >/dev/null
make -j"$MAYHEM_JOBS" -C src/libpcp/src libpcp.a CFLAGS_OPT="-O2 -g $COVERAGE_FLAGS" >/dev/null
mkdir -p "$OUT/pcp-tests"
VK="$SRC/vendor/github.com/valkey-io/libvalkey/src"
$CC -O2 $COVERAGE_FLAGS -DPCP_INTERNAL -I"$SRC/src/include" -I"$SRC/src/include/pcp" -I"$VK" -I"$SRC/vendor/github.com/valkey-io/libvalkey/include/valkey" \
    "$SRC/qa/src/test_encodings.c" "$SRC/src/libpcp_web/src/encoding.c" "$VK/sds.c" "$VK/alloc.c" \
    "$SRC/src/libpcp/src/libpcp.a" -lcmocka $LIBS_SYS -o "$OUT/pcp-tests/test_encodings"
$CC -O2 $COVERAGE_FLAGS -DPCP_INTERNAL -I"$SRC/src/include" -I"$SRC/src/include/pcp" \
    "$SRC/qa/src/test_hostspec.c" "$SRC/src/libpcp/src/libpcp.a" -lcmocka $LIBS_SYS -o "$OUT/pcp-tests/test_hostspec"
# Known-answer tests for the parsers the harnesses fuzz.
$CC -O2 $COVERAGE_FLAGS -DPCP_INTERNAL -I"$SRC/src/include" -I"$SRC/src/include/pcp" \
    "$SRC/mayhem/test_parsers.c" "$SRC/src/libpcp/src/libpcp.a" $LIBS_SYS -o "$OUT/pcp-tests/test_parsers"

# 2) Sanitized libpcp + pmlc with libFuzzer coverage instrumentation and DWARF <= 3.
pcp_clean
if [ -n "$SANITIZER_FLAGS" ]; then
    SAN_CONF=(--enable-asan --enable-ubsan)
    COV_FLAGS="-fsanitize=fuzzer-no-link"
else
    SAN_CONF=()
    COV_FLAGS=""
fi
env -u CFLAGS -u LDFLAGS -u CXXFLAGS ./configure CC="$CC" "${SAN_CONF[@]}" "${CONF[@]}" >/dev/null
make -C src/include >/dev/null
# libpcp does benign "p - 1" / "&s[strlen(s)-1]" arithmetic on empty strings (spec.c, config.c) that
# UBSan's pointer-overflow check flags on trivial inputs; relax only that check, ASan + the rest stay halting.
RELAX="-fno-sanitize=pointer-overflow"
MK=(CFLAGS_OPT="-O2 $DEBUG_FLAGS" CFLAGS_SANITIZER="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $COV_FLAGS")
make -j"$MAYHEM_JOBS" -C src/libpcp/src libpcp.a "${MK[@]}" >/dev/null
make -C src/pmlc gram.h >/dev/null
# pmlc defines yyparse/addindom, which libpcp.a also defines; rename pmlc's so the static link has no clash.
make -j"$MAYHEM_JOBS" -C src/pmlc pmlc.o util.o actions.o lex.o gram.tab.o \
    CFLAGS_OPT="-O2 $DEBUG_FLAGS -Dyyparse=pmlc_yyparse -Daddindom=pmlc_addindom" \
    CFLAGS_SANITIZER="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $COV_FLAGS" >/dev/null
LIBPCP="$SRC/src/libpcp/src/libpcp.a"
SAN="$SANITIZER_FLAGS $DEBUG_FLAGS"
INC="-I$SRC/src/include -I$SRC/src/include/pcp"

# LeakSanitizer off (build time), linked into every fuzz and standalone binary.
$CXX $SAN -c "$SRC/mayhem/lsan_off.cc" -o /tmp/lsan_off.o
$CC $SAN -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o

# pmlc: the pmlogger control CLI reads its commands on stdin.
$CC $SAN $COV_FLAGS /tmp/lsan_off.o "$SRC"/src/pmlc/{pmlc,util,actions,lex,gram.tab}.o "$LIBPCP" $LIBS_SYS -o "$OUT/pmlc"

# libFuzzer harnesses (+ run-once standalone reproducers).
for h in fuzz_pmParse fuzz_pmPDU fuzz_pmns fuzz_pmDerive; do
    $CC $SAN $COV_FLAGS $INC -DPCP_INTERNAL -c "$SRC/mayhem/$h.c" -o "/tmp/$h.o"
    $CC $SAN $LIB_FUZZING_ENGINE "/tmp/$h.o" /tmp/lsan_off.o "$LIBPCP" $LIBS_SYS -o "$OUT/$h"
    $CC $SAN /tmp/standalone_main.o "/tmp/$h.o" /tmp/lsan_off.o "$LIBPCP" $LIBS_SYS -o "$OUT/$h-standalone"
done
# C++ harness (legacy pmnumberstr target): the run-once driver is compiled as C above.
$CXX $SAN $COV_FLAGS -std=c++17 $INC -c "$SRC/mayhem/fuzz_pmNumberStr.cpp" -o /tmp/fuzz_pmNumberStr.o
$CXX $SAN $LIB_FUZZING_ENGINE /tmp/fuzz_pmNumberStr.o /tmp/lsan_off.o "$LIBPCP" $LIBS_SYS -o "$OUT/fuzz_pmNumberStr"
$CXX $SAN /tmp/standalone_main.o /tmp/fuzz_pmNumberStr.o /tmp/lsan_off.o "$LIBPCP" $LIBS_SYS -o "$OUT/fuzz_pmNumberStr-standalone"

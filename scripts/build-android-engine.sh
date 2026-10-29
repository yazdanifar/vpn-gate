#!/bin/bash
# Cross-compiles the in-process Android engine (crates/vpngate-uniffi) for the three ABIs and generates the Kotlin
# bindings. Needs the Android NDK ($ANDROID_NDK_HOME) and runs on macOS or Linux:
#   scripts/build-android-engine.sh [--debug]
# Output (git-ignored, consumed by apps/android from U26 on):
#   build/android-engine/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libvpngate_uniffi.so
#   build/android-engine/kotlin/uniffi/vpngate_uniffi/vpngate_uniffi.kt
set -euo pipefail
cd "$(dirname "$0")/.."
PROFILE=--release
DIR=release
if [ "${1:-}" = "--debug" ]; then PROFILE=; DIR=debug; fi
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to the NDK directory}"
# 24 = Android 7.0, the minimum the app supports.
PLATFORM=24
OUT=build/android-engine

rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
command -v cargo-ndk >/dev/null || cargo install cargo-ndk --locked --version 4.1.2

rm -rf "$OUT"
cargo ndk --platform "$PLATFORM" -t arm64-v8a -t armeabi-v7a -t x86_64 -o "$OUT/jniLibs" \
  build -p vpngate-uniffi --locked $PROFILE

# Library mode reads the interface from the compiled library, so the bindings can never drift from the binary.
cargo run --locked -q -p vpngate-uniffi --features cli --bin uniffi-bindgen -- generate \
  --library "$OUT/jniLibs/arm64-v8a/libvpngate_uniffi.so" --language kotlin --no-format --out-dir "$OUT/kotlin"
find "$OUT" -type f | sort

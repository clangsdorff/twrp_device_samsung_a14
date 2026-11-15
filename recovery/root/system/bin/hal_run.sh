#!/system/bin/sh
. /system/bin/rom_mount.sh

rom_mount || exit 1
vendor_mount || exit 1

SYS="${ROM}/system/lib64/bootstrap:${ROM}/system/lib64"
VEN="/vendor/lib64:/vendor/lib64/hw"
export LD_LIBRARY_PATH="${SYS}:${VEN}"
# vendor binaries take their own copies first, as in the vendor linker namespace; an Android 13 KeyMint HAL fails on an Android 15+ keymint-V2-ndk.
# A vendor with its own libbinder (Android 15+) must not: the system libbinder_ndk then binds to it and misses system-only symbols.
case "$1" in
    /vendor/*) [ -e /vendor/lib64/libbinder.so ] ||
        export LD_LIBRARY_PATH="${ROM}/system/lib64/bootstrap:${VEN}:${ROM}/system/lib64" ;;
esac
export ANDROID_ROOT=/system
export ANDROID_DATA=/data

# the LineageOS vendor ships the stock HALs under a .samsung suffix
bin="$1"
[ -e "${bin}" ] || [ ! -e "${bin}.samsung" ] || { shift; set -- "${bin}.samsung" "$@"; }

exec "${ROM}/system/bin/bootstrap/linker64" "$@"

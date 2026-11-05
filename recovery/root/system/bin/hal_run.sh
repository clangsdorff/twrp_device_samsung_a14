#!/system/bin/sh
. /system/bin/rom_mount.sh

vendor_mount

# the firmware HALs need Android 15 system libraries; these come from A145FXXSEDZF2 and do not depend on the installed ROM
SYS="/system/tee/lib64/bootstrap:/system/tee/lib64"
VEN="/vendor/lib64:/vendor/lib64/hw"
export LD_LIBRARY_PATH="${SYS}:${VEN}"
# vendor binaries take their own copies first, as in the vendor linker namespace; an Android 13 KeyMint HAL fails on the Android 15 keymint-V2-ndk.
# A vendor with its own libbinder (Android 15) must not: the bundled libbinder_ndk then binds to it and misses openDeclaredPassthroughHal
case "$1" in
    /vendor/*) [ -e /vendor/lib64/libbinder.so ] ||
        export LD_LIBRARY_PATH="/system/tee/lib64/bootstrap:${VEN}:/system/tee/lib64" ;;
esac
export ANDROID_ROOT=/system
export ANDROID_DATA=/data

# the LineageOS vendor ships the stock HALs under a .samsung suffix
bin="$1"
[ -e "${bin}" ] || [ ! -e "${bin}.samsung" ] || { shift; set -- "${bin}.samsung" "$@"; }

exec /system/bin/tee_linker64 "$@"

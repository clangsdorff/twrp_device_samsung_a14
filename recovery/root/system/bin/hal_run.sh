#!/system/bin/sh
. /system/bin/rom_mount.sh

vendor_mount

# the firmware HALs need Android 15 system libraries; these come from A145FXXSEDZF2 and do not depend on the installed ROM
SYS="/system/tee/lib64/bootstrap:/system/tee/lib64"
VEN="/vendor/lib64:/vendor/lib64/hw"
# vendor binaries take their own copies first, as in the vendor linker namespace; an Android 13 KeyMint HAL fails on the Android 15 keymint-V2-ndk
case "$1" in
    /vendor/*) export LD_LIBRARY_PATH="/system/tee/lib64/bootstrap:${VEN}:/system/tee/lib64" ;;
    *) export LD_LIBRARY_PATH="${SYS}:${VEN}" ;;
esac
export ANDROID_ROOT=/system
export ANDROID_DATA=/data

exec /system/bin/tee_linker64 "$@"

#!/system/bin/sh
. /system/bin/rom_mount.sh

rom_mount
vendor_mount

export LD_LIBRARY_PATH="${ROM}/system/lib64/bootstrap:${ROM}/system/lib64:/vendor/lib64:/vendor/lib64/hw"
export ANDROID_ROOT=/system
export ANDROID_DATA=/data

exec "${ROM}/system/bin/bootstrap/linker64" "$@"

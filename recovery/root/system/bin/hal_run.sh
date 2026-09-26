#!/system/bin/sh
. /system/bin/rom_mount.sh

vendor_mount

# the firmware HALs need Android 15 system libraries; these come from A145FXXSEDZF2 and do not depend on the installed ROM
export LD_LIBRARY_PATH="/system/tee/lib64/bootstrap:/system/tee/lib64:/vendor/lib64:/vendor/lib64/hw"
export ANDROID_ROOT=/system
export ANDROID_DATA=/data

exec /system/bin/tee_linker64 "$@"

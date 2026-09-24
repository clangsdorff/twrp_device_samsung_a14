#!/system/bin/sh
# init exports TMPDIR=/data/local/tmp, which does not exist here, and mksh needs it for heredocs
export TMPDIR=/tmp
LOG=/tmp/decrypt.log
exec >>"${LOG}" 2>&1
. /system/bin/decrypt_stack.sh

echo "===== decrypt, uptime $(cat /proc/uptime 2>/dev/null) ====="

mountpoint -q /metadata 2>/dev/null || mount -t ext4 /dev/block/by-name/metadata /metadata 2>/dev/null
KEYDIR=/metadata/vold/metadata_encryption
if [ ! -e "${KEYDIR}/key" ]; then
    echo "no metadata key in ${KEYDIR}, /data is not encrypted on this firmware - stopping"
    echo "===== decrypt done ====="
    exit 0
fi

if ! stack_up; then
    stack_down
    echo "===== decrypt done ====="
    exit 0
fi

USERDATA=$(readlink -f /dev/block/by-name/userdata)
echo "userdata: ${USERDATA}"

# a dm-default-key device left over from an earlier attempt makes DM_DEV_CREATE fail with EBUSY
if [ -e /dev/block/mapper/userdata ] && ! grep -qE ' /data ' /proc/mounts; then
    rom dmctl delete userdata >/dev/null 2>&1
fi

mt=0
while [ "${mt}" -lt 5 ]; do
    grep -qE ' /data ' /proc/mounts && break
    rom vdc cryptfs mountFstab "${USERDATA}" /data false "" 2>&1
    grep -qE ' /data ' /proc/mounts && break
    rom vdc cryptfs mountFstab "${USERDATA}" /data false 2>&1
    grep -qE ' /data ' /proc/mounts && break
    rom vdc cryptfs mountFstab "${USERDATA}" /data 2>&1
    grep -qE ' /data ' /proc/mounts && break
    mt=$((mt + 1))
    [ "${mt}" -lt 5 ] && sleep 3
done

if ! grep -qE ' /data ' /proc/mounts; then
    echo "/data not mounted, see the vdc output above"
    stack_down
    echo "===== decrypt done ====="
    exit 0
fi
echo "/data mounted: $(grep -E ' /data ' /proc/mounts)"

rom vdc cryptfs enablefilecrypto 2>&1
rom vdc cryptfs init_user0 2>&1
echo "fscrypt keys after DE: $(grep -c fscrypt /proc/keys 2>/dev/null)"

/system/bin/hal_run.sh /system/bin/ce_unlock 2>&1
echo "fscrypt keys after CE: $(grep -c fscrypt /proc/keys 2>/dev/null)"

# the recovery decided /data was encrypted before this script mounted it, and its own
# decrypt path cannot clear the flag on this device
if [ -d /data/data/android ]; then
    /system/bin/twrp set tw_is_encrypted 0 >/dev/null 2>&1
elif [ -s /tmp/.ce_pwtype ]; then
    /system/bin/twrp set tw_crypto_pwtype_0 "$(cat /tmp/.ce_pwtype)" >/dev/null 2>&1
fi

# /sdcard was set up as a bare ramdisk directory because /data was not mounted yet
if [ -d /data/media/0 ] && ! grep -q " /sdcard " /proc/mounts; then
    mount -o bind /data/media/0 /sdcard
fi

echo "----- log -----"
logcat -d 2>/dev/null | grep -iE 'keymint|keystore|vold|teegris|tzdaemon|servicemanager|vintf|cryptfs' | tail -60

stack_down
echo "===== decrypt done ====="

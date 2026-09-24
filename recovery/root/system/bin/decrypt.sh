#!/system/bin/sh
# init exports TMPDIR=/data/local/tmp, which does not exist here, and mksh needs it for heredocs
export TMPDIR=/tmp
LOG=/tmp/decrypt.log
exec >>"${LOG}" 2>&1
. /system/bin/decrypt_stack.sh

echo "===== decrypt, uptime $(cat /proc/uptime 2>/dev/null) ====="

KEYDIR=/metadata/vold/metadata_encryption
mkdir -p /metadata 2>/dev/null
if grep -q ' /metadata ' /proc/mounts; then
    mount -o remount,ro /metadata
else
    mount -t ext4 -o ro /dev/block/by-name/metadata /metadata
fi
echo "metadata: $(grep ' /metadata ' /proc/mounts)"
if [ ! -e "${KEYDIR}/key/encrypted_key" ]; then
    echo "no metadata key in ${KEYDIR}, /data is not encrypted on this firmware - stopping"
    echo "===== decrypt done ====="
    exit 0
fi

# the metadata partition holds every KeyMint-wrapped key vold needs; keep a copy to restore from
[ -s /tmp/metadata-backup.img ] ||
    dd if=/dev/block/by-name/metadata of=/tmp/metadata-backup.img bs=1048576 2>/dev/null
echo "metadata backup: $(ls -l /tmp/metadata-backup.img 2>/dev/null)"

if ! stack_up; then
    stack_down
    echo "===== decrypt done ====="
    exit 0
fi

decrypt() { /system/bin/hal_run.sh /system/bin/langsdorff_decrypt "$@"; }

# userdata is mounted at an anchor the recovery never touches: fscrypt keys live on the
# superblock, and this reference keeps them when the recovery unmounts and remounts /data
ANCHOR=/tmp/.userdata
USERDATA=$(readlink -f /dev/block/by-name/userdata)
mkdir -p "${ANCHOR}"
if ! grep -q " ${ANCHOR} " /proc/mounts; then
    decrypt metadata "${USERDATA}" &&
        mount -t f2fs -o noatime,nosuid,nodev,discard,usrquota,grpquota,fsync_mode=nobarrier,reserve_root=32768,resgid=5678,inlinecrypt \
            /dev/block/mapper/userdata "${ANCHOR}"
fi

if grep -q " ${ANCHOR} " /proc/mounts; then
    echo "userdata mounted: $(grep " ${ANCHOR} " /proc/mounts)"
    decrypt de && decrypt ce
    echo "ce exit: $?"
    # the recovery mounts /data from the mapper itself and then sets up /sdcard and MTP
    grep -q ' /data ' /proc/mounts || /system/bin/twrp mount /data >/dev/null 2>&1
    grep -q ' /data ' /proc/mounts || mount --bind "${ANCHOR}" /data
else
    echo "userdata not mounted"
fi

# the recovery decided /data was encrypted before this script mounted it, and its own
# decrypt path cannot clear the flag on this device
if [ -d /data/media/0/Android ] || [ -d /data/data/android ]; then
    /system/bin/twrp set tw_is_encrypted 0 >/dev/null 2>&1
elif [ -s /tmp/.ce_pwtype ]; then
    /system/bin/twrp set tw_crypto_pwtype_0 "$(cat /tmp/.ce_pwtype)" >/dev/null 2>&1
fi

# /sdcard was set up as a bare ramdisk directory because /data was not mounted yet
if [ -d /data/media/0 ] && ! grep -q " /sdcard " /proc/mounts; then
    mount -o bind /data/media/0 /sdcard
fi

echo "----- log -----"
logcat -d 2>/dev/null | grep -iE 'keymint|langsdorff_decrypt|teegris|tzdaemon|servicemanager|vintf' | tail -60

stack_down
echo "===== decrypt done ====="

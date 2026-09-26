#!/system/bin/sh
export TMPDIR=/tmp
exec >>/tmp/decrypt.log 2>&1
. /system/bin/rom_mount.sh

echo "===== data_release ====="
for m in /sdcard /data /tmp/.userdata; do
    grep -q " ${m} " /proc/mounts && umount "${m}"
done
/system/bin/hal_run.sh /system/tee/bin/dmctl delete userdata
# langsdorff_decrypt created this link itself, so nothing else removes it
rm -f /dev/block/mapper/userdata
umount /vendor "${ROM}" 2>/dev/null
echo "userdata still mapped: $(grep -c mapper/userdata /proc/mounts), link: $([ -e /dev/block/mapper/userdata ] && echo yes || echo no)"
[ ! -e /dev/block/mapper/userdata ] && ! grep -q mapper/userdata /proc/mounts

#!/system/bin/sh
export TMPDIR=/tmp
exec >>/tmp/decrypt.log 2>&1
. /system/bin/decrypt_stack.sh

echo "===== decrypt_user, credential given: $([ -n "$1" ] && echo yes || echo no) ====="
stack_up || { stack_down; exit 1; }

/system/bin/hal_run.sh /system/bin/langsdorff_decrypt ce "$1"
rc=$?
echo "ce exit: ${rc}"

if [ "${rc}" = 0 ] && [ -d /data/media/0 ] && ! grep -q " /sdcard " /proc/mounts; then
    mount -o bind /data/media/0 /sdcard
fi

stack_down
exit "${rc}"

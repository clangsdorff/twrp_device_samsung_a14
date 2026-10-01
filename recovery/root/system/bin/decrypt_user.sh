#!/system/bin/sh
export TMPDIR=/tmp
exec >>/tmp/decrypt.log 2>&1
. /system/bin/decrypt_stack.sh

CREDENTIAL="${TW_CRYPTO_PASSWORD}"
unset TW_CRYPTO_PASSWORD

echo "===== decrypt_user, credential given: $([ -n "${CREDENTIAL}" ] && echo yes || echo no) ====="
vendor_ready || exit 1
stack_up || { stack_down; exit 1; }

/system/bin/hal_run.sh /system/bin/langsdorff_decrypt ce "${CREDENTIAL}"
rc=$?
echo "ce exit: ${rc}"

if [ "${rc}" = 0 ] && [ -d /data/media/0 ] && ! grep -q " /sdcard " /proc/mounts; then
    mount -o bind /data/media/0 /sdcard
fi

stack_down
exit "${rc}"

#!/system/bin/sh
export TMPDIR=/tmp
KEYDIR=/metadata/vold/metadata_encryption
FSTAB=/system/etc/recovery.fstab
LOG=/tmp/fstab_crypto.log

mkdir -p /metadata 2>/dev/null
mounted=0
if ! mountpoint -q /metadata 2>/dev/null; then
    mount -t ext4 -o ro /dev/block/by-name/metadata /metadata 2>/dev/null && mounted=1
fi

if [ -e "${KEYDIR}/key/encrypted_key" ]; then
    opts="inlinecrypt"
    flags="fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized,keydirectory=${KEYDIR}"
    awk -v o="${opts}" -v f="${flags}" '
        $2 == "/data" && $0 !~ /^#/ { print $1 "\t" $2 "\t" $3 "\t" $4 "," o "\t" $5 "," f; next }
        { print }
    ' "${FSTAB}" > /tmp/recovery.fstab.crypto
    cp /tmp/recovery.fstab.crypto "${FSTAB}"
    echo "metadata encryption present, /data flagged" > "${LOG}"
else
    echo "no metadata key, fstab left plain" > "${LOG}"
fi
grep -E "[[:space:]]/data[[:space:]]" "${FSTAB}" >> "${LOG}"

[ "${mounted}" = 1 ] && umount /metadata 2>/dev/null
exit 0

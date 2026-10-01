#!/system/bin/sh
. /system/bin/rom_mount.sh

TEE_SERVICES="tee-gatekeeper tee-keymint tee-tzts tee-tzdaemon tee-servicemanager"
VENDOR_BINS="/vendor/bin/tzdaemon /vendor/bin/tzts_daemon /vendor/bin/hw/android.hardware.security.keymint-service /vendor/bin/hw/android.hardware.gatekeeper@1.0-service"

# libbinder waits forever for a context manager that is not there
registered() { timeout 3 /system/bin/hal_run.sh /system/tee/bin/service check "$1" 2>/dev/null | grep -q ": found"; }

wait_prop() {
    n=0
    while [ "${n}" -lt "$3" ]; do
        [ "$(getprop "$1")" = "$2" ] && return 0
        n=$((n + 1))
        sleep 0.5
    done
    return 1
}

wait_service() {
    n=0
    while [ "${n}" -lt "$3" ]; do
        registered "$1" && return 0
        [ "$(getprop "init.svc.$2")" = running ] || return 1
        n=$((n + 1))
        sleep 0.5
    done
    return 1
}

# libvintf 4.0 rejects the vendor manifest whole over its version 8.0 and the radio HALs' <version>202404</version>.
# The bind also keeps /vendor busy: the recovery mounts it on its own while it starts and unmounts whatever is there when done
vendor_pin() {
grep -q ' /vendor/etc/vintf ' /proc/mounts && [ -e /vendor/bin/tzdaemon ] && return 0
umount /vendor/etc/vintf 2>/dev/null
vendor_mount || return 1
rm -rf /tmp/vintf
mkdir -p /tmp/vintf/manifest
cat > /tmp/vintf/manifest.xml <<'XML'
<manifest version="1.0" type="device" target-level="6">
    <hal format="hidl" override="true">
        <name>android.hardware.gatekeeper</name>
        <transport>hwbinder</transport>
        <fqname>@1.0::IGatekeeper/default</fqname>
    </hal>
    <hal format="aidl" override="true">
        <name>android.hardware.security.keymint</name>
        <version>2</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>2</version>
        <fqname>IRemotelyProvisionedComponent/default</fqname>
    </hal>
    <hal format="aidl" override="true">
        <name>android.hardware.security.secureclock</name>
        <fqname>ISecureClock/default</fqname>
    </hal>
    <hal format="aidl" override="true">
        <name>android.hardware.security.sharedsecret</name>
        <fqname>ISharedSecret/default</fqname>
    </hal>
    <hal format="aidl">
        <name>vendor.samsung.hardware.keymint</name>
        <version>2</version>
        <fqname>ISehKeyMintExtension/default</fqname>
    </hal>
    <hal format="aidl">
        <name>vendor.samsung.hardware.keymint</name>
        <version>2</version>
        <fqname>ISehKeyMintFactory/default</fqname>
    </hal>
</manifest>
XML
sed -e 's/version="8.0"/version="1.0"/g' -e 's/level="[0-9]*"/level="6"/g' \
    /vendor/etc/vintf/compatibility_matrix.xml > /tmp/vintf/compatibility_matrix.xml 2>/dev/null
chmod -R 755 /tmp/vintf
mount -o bind /tmp/vintf /vendor/etc/vintf && [ -e /vendor/bin/tzdaemon ]
}

# the recovery maps every logical partition at once, so a vendor missing once system is there never comes;
# twrp.crash_counter is set once the recovery is past its fstab, which mounts /vendor and unmounts it again
vendor_ready() {
n=0
while [ "${n}" -lt 60 ]; do
    [ -e /dev/block/mapper/system ] && [ -n "$(getprop twrp.crash_counter)" ] && break
    n=$((n + 1))
    sleep 0.5
done

vendor_mount
missing=""
for b in ${VENDOR_BINS}; do
    [ -e "${b}" ] || missing="${missing} ${b}"
done
if [ -n "${missing}" ]; then
    echo "vendor is missing:${missing}"
    echo "skipping decryption"
    umount /vendor 2>/dev/null
    return 1
fi

n=0
until vendor_pin; do
    n=$((n + 1))
    if [ "${n}" -ge 10 ]; then
        echo "vendor cannot be kept mounted"
        umount /vendor/etc/vintf 2>/dev/null
        umount /vendor 2>/dev/null
        return 1
    fi
    sleep 0.5
done
}

stack_up() {
rom_mount
echo "rom: $(rom_mounted && echo yes || echo no) vendor: $([ -e /vendor/bin/tzdaemon ] && echo yes || echo no)"

mkdir -p /mnt/vendor/efs 2>/dev/null
mount | grep -q ' /mnt/vendor/efs ' ||
    mount -t ext4 /dev/block/bootdevice/by-name/efs /mnt/vendor/efs 2>/dev/null
mkdir -p /mnt/vendor/efs/tee /dev/socket/iwt/ca 2>/dev/null
chmod 0770 /dev/socket/iwt /dev/socket/iwt/ca 2>/dev/null

# /odm/etc -> /vendor/odm/etc -> /odm is a symlink loop, and libvintf fails the whole device manifest on it
if [ -L /odm/etc ]; then
    rm -f /odm/etc
    mkdir -p /odm/etc/vintf
fi

prop_from() { grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2-; }
RP=/system/bin/resetprop
SYS_BP="${ROM}/system/build.prop"
VEN_BP=/vendor/build.prop

# KeyMint refuses a key created under a newer OS than the one the recovery reports, and the
# TA takes its slow eng path unless the fingerprint parses as a user build
for pair in "ro.build.version.release:ro.build.version.release" \
            "ro.build.fingerprint:ro.system.build.fingerprint" \
            "ro.build.type:ro.system.build.type" \
            "ro.build.tags:ro.system.build.tags" \
            "ro.build.version.security_patch:ro.build.version.security_patch"; do
    v=$(prop_from "${SYS_BP}" "${pair##*:}")
    [ -n "${v}" ] && "${RP}" "${pair%%:*}" "${v}" 2>/dev/null
done
v=$(prop_from "${VEN_BP}" ro.vendor.build.security_patch)
[ -n "${v}" ] && "${RP}" ro.vendor.build.security_patch "${v}" 2>/dev/null

echo "props: release=$(getprop ro.build.version.release) type=$(getprop ro.build.type)"

# the 12.1 servicemanager fails addService from the firmware HALs, so /dev/binder goes to the firmware's own
setprop ctl.stop servicemanager
sleep 1
setprop ctl.restart tee-servicemanager
wait_prop init.svc.tee-servicemanager running 20
setprop servicemanager.ready true
echo "servicemanager: $(getprop init.svc.tee-servicemanager)"
[ "$(getprop init.svc.tee-servicemanager)" = running ] || return 1

setprop ctl.restart tee-tzdaemon
wait_prop vendor.tzdaemon Ready 30
echo "tzdaemon: $(getprop vendor.tzdaemon)"
[ "$(getprop vendor.tzdaemon)" = Ready ] || return 1

setprop ctl.restart tee-tzts
wait_prop vendor.tzts_daemon Ready 20
echo "tzts_daemon: $(getprop vendor.tzts_daemon)"
[ "$(getprop vendor.tzts_daemon)" = Ready ] || return 1

setprop ctl.restart tee-keymint
wait_service android.hardware.security.keymint.IKeyMintDevice/default tee-keymint 40
echo "keymint: $(registered android.hardware.security.keymint.IKeyMintDevice/default && echo registered || echo MISSING)"
registered android.hardware.security.keymint.IKeyMintDevice/default || return 1

setprop ctl.restart hwservicemanager
sleep 2
setprop ctl.restart tee-gatekeeper
sleep 2
echo "gatekeeper: $(getprop init.svc.tee-gatekeeper)"

}

# every one of these holds /vendor or /rom open and the recovery cannot flash a zip
# while they do; the fscrypt keys stay in the kernel keyring once installed
stack_down() {
for s in ${TEE_SERVICES}; do
    setprop ctl.stop "${s}"
done
sleep 2

# tzdaemon runs as root here, the firmware's cannot open what this one created and gatekeeper
# then rejects every credential; the recovery policy also leaves it unlabeled. The top
# directories come from the firmware's init, so they carry its owner and label.
for d in /data/vendor/tee /mnt/vendor/efs/tee; do
    [ -d "${d}" ] || continue
    owner=$(stat -c %u:%g "${d}")
    label=$(stat -c %C "${d}")
    [ "${owner}" = 0:0 ] && continue
    case "${label}" in *unlabeled*|"") continue ;; esac
    chown -R "${owner}" "${d}"
    chcon -R "${label}" "${d}"
done

for m in /vendor/etc/vintf /mnt/vendor/efs /vendor "${ROM}"; do
    umount "${m}" 2>/dev/null
done
echo "stack down, /vendor and /rom still mounted: $(grep -cE ' /vendor | /rom ' /proc/mounts)"
}

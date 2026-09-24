#!/system/bin/sh
. /system/bin/rom_mount.sh

TEE_SERVICES="tee-gatekeeper tee-keymint tee-tzts tee-tzdaemon tee-servicemanager"

rom() { /system/bin/hal_run.sh "${ROM}/system/bin/$@"; }

registered() { rom service check "$1" 2>/dev/null | grep -q ": found"; }

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
    while [ "${n}" -lt "$2" ]; do
        registered "$1" && return 0
        n=$((n + 1))
        sleep 0.5
    done
    return 1
}

stack_up() {
n=0
while [ "${n}" -lt 60 ]; do
    [ -e /dev/block/mapper/vendor ] && [ -e /dev/block/mapper/system ] && break
    n=$((n + 1))
    sleep 0.5
done

rom_mount
vendor_mount
echo "rom: $(rom_mounted && echo yes || echo no) vendor: $([ -e /vendor/bin/tzdaemon ] && echo yes || echo no)"
rom_mounted || return 1
[ -e /vendor/bin/tzdaemon ] || return 1

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

# libvintf 4.0 rejects the vendor manifest whole over its version 8.0 and the radio HALs' <version>202404</version>
if ! mount | grep -q ' /vendor/etc/vintf '; then
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
    mount -o bind /tmp/vintf /vendor/etc/vintf
fi

# the ramdisk ships no service_contexts, so servicemanager has no label for the keymint names
[ -e /plat_service_contexts ] ||
    cp "${ROM}/system/etc/selinux/plat_service_contexts" /plat_service_contexts 2>/dev/null
chmod 644 /plat_service_contexts 2>/dev/null

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

setprop ctl.restart tee-tzdaemon
wait_prop vendor.tzdaemon Ready 30
echo "tzdaemon: $(getprop vendor.tzdaemon)"

setprop ctl.restart tee-tzts
wait_prop vendor.tzts_daemon Ready 20
echo "tzts_daemon: $(getprop vendor.tzts_daemon)"

setprop ctl.restart tee-keymint
wait_service android.hardware.security.keymint.IKeyMintDevice/default 40
echo "keymint: $(registered android.hardware.security.keymint.IKeyMintDevice/default && echo registered || echo MISSING)"

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

# the dm-default-key "userdata" mapper holds the raw partition open, and format data's
# mkfs then fails with "Error: In use by the system!"
if [ -e /dev/block/mapper/userdata ] && ! grep -q ' /data ' /proc/mounts; then
    rom dmctl delete userdata 2>/dev/null && rm -f /dev/block/mapper/userdata
fi

for m in /vendor/etc/vintf /mnt/vendor/efs /vendor "${ROM}"; do
    umount "${m}" 2>/dev/null
done
echo "stack down, /vendor and /rom still mounted: $(grep -cE ' /vendor | /rom ' /proc/mounts)"
}

# TWRP device tree for Samsung Galaxy A14 (SM-A145F)

TWRP 3.7.1 (`twrp-12.1`) device tree for the Galaxy A14 4G, built with
[langsdorffkernel](https://github.com/clangsdorff/langsdorffkernel).

| | |
|---|---|
| Device | Samsung Galaxy A14 (`a14`, SM-A145F) |
| SoC | Exynos 850 (s5e3830), 8x Cortex-A55 |
| Kernel | langsdorffkernel 5.10 (`pn` variant: permissive, no root, no overclock) |
| Firmware base | A145FXXSEDZF2 (Android 15 / One UI 7) |
| Partitions | Non-A/B, dynamic partitions (super), erofs |
| Recovery | Dedicated `recovery` partition, boot header v2 |

## Status

- [ ] Boots
- [ ] Touch, display, brightness
- [ ] ADB / MTP
- [ ] Backup / restore
- [ ] Decryption (FBE v2 + metadata encryption): implemented, untested

## How it works

On this device the bootloader does **not** load `vendor_boot` when it boots
recovery. The recovery image has to carry everything itself, the same way
stock recovery does:

- **Kernel:** taken from the langsdorffkernel release `boot.img`
- **dtb:** taken from the release `vendor_boot.img`
- **recovery_dtbo:** stock `dtbo.img` (`prebuilt/dtbo.img`)
- **Kernel modules and touch firmware:** extracted from the release
  `vendor_boot.img` ramdisks into the recovery ramdisk. The modules are loaded
  by first stage init through `modules.load.recovery`.

`scripts/prepare_kernel.py` does the extraction. The workflow runs it before
every build, so the kernel files are never committed.

The SELinux mode is hardcoded in each kernel variant. Recovery uses the
permissive `pn` build.

## Decryption

The 12.1 fscrypt code needs a keymaster 4 HIDL HAL, and this firmware only has
KeyMint AIDL. The recovery therefore mounts the firmware's `system` and
`vendor` and runs only what talks to the TEE: the TEEGRIS daemons,
servicemanager, KeyMint and gatekeeper. `langsdorff_decrypt` then unlocks
three layers itself:

- **Metadata:** the `metadata_encryption` key, then a dm-default-key device
  for `/data`.
- **Device encrypted (DE):** the system and user 0 DE keys.
- **Credential encrypted (CE):** the synthetic password from
  `locksettings.db` and `spblob`, then the user 0 CE key.

The firmware's vold and keystore2 never run. When KeyMint asks for a key
upgrade, vold writes the upgraded key over the old one and deletes the old one
from KeyMint; if the recovery reports a newer OS or patch level than the
firmware, the firmware can no longer use its keys. `langsdorff_decrypt` only
reads key files, refuses upgrades instead of performing them, and never deletes
a key. `/metadata` is mounted read-only and a raw copy of it is kept in
`/tmp/metadata-backup.img`. The recovery header takes its OS version and
patch level from the kernel release's `boot.img`.

`fstab_crypto.sh` adds the FBE flags to `/data` only when the firmware has a
metadata key, so the same image also works on unencrypted ROMs.

## Building

Builds run on GitHub Actions (`.github/workflows/build.yml`):

- **Trigger:** a push to `main`, or **Actions → Build TWRP → Run workflow**.
  A manual run lets you pick the kernel release tag and variant.
- **Cache:**
  - compiler output (ccache, content-hashed): a small change recompiles only
    the files it touches
  - repo source (`.repo`, refreshed monthly): `repo sync` only fetches what
    changed upstream
  - the kernel release is downloaded fresh on every run
- **Output:** uploaded to [Gofile](https://gofile.io). The download link
  appears in the job summary.

Optional secret:

| Secret | Purpose |
|---|---|
| `GOFILE_TOKEN` | Upload into your Gofile account instead of an expiring guest folder |

### Local build

```bash
repo init --depth=1 -u https://github.com/minimal-manifest-twrp/platform_manifest_twrp_aosp.git -b twrp-12.1
repo sync -c --no-clone-bundle --no-tags --optimized-fetch --prune --force-sync
git clone https://github.com/clangsdorff/twrp_device_samsung_a14 device/samsung/a14

# boot.img and vendor_boot.img from langsdorff@<ver>pn_a14.tar (lz4 -d first)
python3 device/samsung/a14/scripts/prepare_kernel.py \
    --boot boot.img --vendor-boot vendor_boot.img --device-dir device/samsung/a14

export ALLOW_MISSING_DEPENDENCIES=true
source build/envsetup.sh
lunch twrp_a14-eng
mka recoveryimage
```

## Flashing

You need an unlocked bootloader and disabled vbmeta verification. The
langsdorffkernel release ships a `vbmeta.img` with verification disabled.

1. Boot into Download mode.
2. In Odin, put the `.tar.md5` file in the **AP** slot and turn off
   **Auto Reboot**.
3. Flash, then boot straight into recovery with **Volume Up + Power** while
   the USB cable is connected.

## Tree layout

```
BoardConfig.mk                      board and TWRP configuration
device.mk / twrp_a14.mk             product definition
recovery.fstab                      partitions (AOSP v2 format)
recovery/root/system/etc/twrp.flags TWRP display names, backup and storage flags
recovery/root/init.recovery.s5e3830.rc  USB controller, watchdogd
prebuilt/dtbo.img                   stock recovery_dtbo
scripts/prepare_kernel.py           kernel release to prebuilts
recovery/root/system/bin/decrypt*.sh firmware security stack and unlock flow
decrypt/                            langsdorff_decrypt and gk_verify
patches/                            bootable/recovery patches applied by CI
```

## Credits

- [TeamWin](https://github.com/TeamWin) for TWRP
- [minimal-manifest-twrp](https://github.com/minimal-manifest-twrp) for the manifest

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
- [ ] Decryption (FBE v2 + metadata encryption): not implemented yet

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

## Building

Builds run on GitHub Actions (`.github/workflows/build.yml`):

- **Trigger:** a push to `main`, or **Actions → Build TWRP → Run workflow**.
  A manual run lets you pick the kernel release tag and variant.
- **Caches:** the repo source (refreshed monthly), ccache and the kernel
  release.
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
```

## Credits

- [TeamWin](https://github.com/TeamWin) for TWRP
- [minimal-manifest-twrp](https://github.com/minimal-manifest-twrp) for the manifest

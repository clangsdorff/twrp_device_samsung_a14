# Patches

Applied to `bootable/recovery` by the build workflow after the sync. The build
fails if one no longer applies.

- **0001**: `GUIAction::decrypt` goes through `Decrypt_Device`, which on this
  device falls into the FDE path and aborts, because the 12.1 fscrypt code wants
  a keymaster 4 HIDL HAL and the firmware only has KeyMint AIDL. The patch hands
  the typed credential to `decrypt_user.sh` instead.
- **0002**: `Setup_Super_Partition` builds the synthetic `/super` entry with
  `Setup_Image`, which never sizes a block device that is not mounted, so the
  backup screen shows it as 0MB. The patch sizes it from the block device.
- **0003**: `Find_Actual_Block_Device` resolves `/data` to the raw userdata
  partition, which is ciphertext under metadata encryption. Once
  `langsdorff_decrypt` has created `/dev/block/mapper/userdata`, the patch makes
  every mount of `/data` use that instead.
- **0004**: fb0 reports BGRA offsets but DECON scans out RGBA, and the
  `RECOVERY_BGRA` swap works in place on a buffer TWRP only partly redraws, so
  most of the screen stays swapped. The patch renders RGBA directly. It also
  drops the powerdown blank in `fbdev_init`: powering the panel down there
  stalls the unblank until the NVT touch self test gives up, about 10 s of black
  screen. The unblank stays, since DECON drops every pan until it leaves INIT.
- **0005**: Format Data runs `make_f2fs` on whatever `Find_Actual_Block_Device`
  returns, which after 0003 is the dm-default-key device, still mounted at the
  decrypt anchor. The patch runs `data_release.sh` first, which unmounts it and
  removes the device, so the raw partition is formatted and TWRP then wipes
  `/metadata` as before.
- **0006**: When the gadget is unbound under it (sideload switches USB to
  adb only), the MTP server leaves `run()` with its control endpoint closed
  and starts the next `run()` on that closed handle. That run fails and
  reopens `ep0` only then, typically after USB is back to `mtp,adb`. The
  function is mounted with `no_disconnect=1`, so reopening a deactivated
  instance makes the kernel reset it and unregister the whole gadget, and USB
  stays down. The patch reopens `ep0` and rewrites the descriptors as soon as
  a run ends, while the gadget is still unbound.

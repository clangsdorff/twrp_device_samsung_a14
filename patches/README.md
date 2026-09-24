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
  drops the blank/unblank in `fbdev_init`: powering the panel down there stalls
  the unblank until the NVT touch self test gives up, about 10 s of black screen.

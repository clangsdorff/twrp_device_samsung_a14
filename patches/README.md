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

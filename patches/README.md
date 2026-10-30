# Patches

Applied to `bootable/recovery` by the build workflow after the sync. The build
fails if one no longer applies.

- **0001**: `GUIAction::decrypt` goes through `Decrypt_Device`, which on this
  device falls into the FDE path and aborts, because the 12.1 fscrypt code wants
  a keymaster 4 HIDL HAL and the firmware only has KeyMint AIDL. The patch hands
  the typed credential to `decrypt_user.sh` instead, through the environment:
  `Exec_Cmd` writes the command line to the log and to the screen.
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
- **0007**: `Setup_Data_Media` runs before `decrypt.sh` brings the metadata
  layer up, cannot see `/data/media/0` and settles on `/data/media`, so the
  later mount of `/data` binds that to `/sdcard` and MTP, and user 0's files
  show up under `/sdcard/0`. The patch moves the storage path to
  `/data/media/0` on the first mount that can see it and re-adds the MTP
  storage; the MTP side now replaces a storage it already has under the same
  ID instead of listing it twice.
- **0008**: Logical partitions never get `Can_Flash_Img`, and even with the
  `flashimg` flag `Flash_Image` rejects them because their erofs entry backs
  up as files. The patch sends a logical partition down its own path: it
  resizes the partition in the super metadata to the image size, like
  fastbootd, remaps it writable, and writes the image raw or through simg2img.
  An empty image or a bad sparse header is refused before the metadata is
  touched, since a partition resized to 0 cannot be mapped again. Only the
  metadata slot in use is written; the other slot of this super holds an older
  table. `Flash_Sparse_Image` now returns simg2img's result instead of always
  succeeding.
- **0009**: `Decrypt_Data` calls vold's `fscrypt_mount_metadata_encrypted`,
  which waits 30 s for a keystore2 that cannot reach the firmware KeyMint and
  then fails, all on the splash screen. `decrypt.sh` could only start once the
  recovery was past that, and then mounted `/data` through ORS, which flashed
  the action page over the main screen. The patch signals `decrypt.sh` with
  `twrp.fstab.done` once `/vendor` is free, waits on the splash for it to exit,
  mounts `/data` from the mapper and sets the encryption state itself, from
  the keys `langsdorff_decrypt` installed rather than from what `/data` shows:
  a restored backup can leave plaintext CE directories behind.
- **0010**: libtar names each directory's fscrypt policy in a backup by looking
  its key up in the maps the recovery's own fscrypt code fills, and maps the
  name back on restore. That code never runs here, so every policy was dropped
  from the backup and restored directories came back unencrypted. The patch
  looks the keys up in `/tmp/.fscrypt_refs` first, which `langsdorff_decrypt`
  writes as it installs each key, under the names the recovery uses. On
  restore `th_read` sized the policy copy by a version field malloc left
  uninitialized, so only part of the policy came back; it now takes the
  version from the header first.
- **0011**: a zip's updater unmounts `/data` but not the `/sdcard` bind, which
  `Is_Mounted` still counts as `/data` being mounted, so the recovery never
  mounts it again and every size after the flash reads 0. `Mount` now tells a
  stale bind from a mounted `/data`, mounts `/data` writable and replaces the
  bind only after that, since the old bind is what keeps the fscrypt keys.

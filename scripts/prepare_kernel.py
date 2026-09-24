#!/usr/bin/env python3
#
# Copyright (C) 2026 The Android Open Source Project
#
# SPDX-License-Identifier: Apache-2.0
#
"""Turn a langsdorffkernel release (boot.img + vendor_boot.img) into the
prebuilts this device tree expects.

Samsung's recovery partition is a standalone boot header v2 image, so the
bootloader never loads vendor_boot when booting recovery. Everything the
kernel needs at runtime therefore has to be pulled out of the release images
and put into the recovery ramdisk:

  boot.img (v4)         -> prebuilt/kernel
  vendor_boot.img (v4)  -> prebuilt/dtb.img
    ramdisk "dlkm"      -> recovery/root/lib/modules/*   (+ modules.load.recovery)
    ramdisk "platform"  -> recovery/root/vendor/firmware/* (touch firmware)
"""

import argparse
import gzip
import os
import shutil
import struct
import subprocess
import sys

BOOT_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
GZIP_MAGIC = b"\x1f\x8b"

VENDOR_RAMDISK_TYPE_PLATFORM = 1
VENDOR_RAMDISK_TYPE_DLKM = 3


def align(value, page_size):
    return (value + page_size - 1) // page_size * page_size


def die(msg):
    sys.exit(f"prepare_kernel: error: {msg}")


def extract_kernel(boot):
    if boot[:8] != BOOT_MAGIC:
        die("boot.img: bad magic")
    kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from("<4I", boot, 8)
    header_version = struct.unpack_from("<I", boot, 40)[0]
    if header_version not in (3, 4):
        die(f"boot.img: unsupported header version {header_version}")
    # v3/v4 boot images always use 4096 byte pages
    return boot[4096:4096 + kernel_size], os_version


def decode_os_version(packed):
    version, patch = packed >> 11, packed & 0x7ff
    a, b, c = (version >> 14) & 0x7f, (version >> 7) & 0x7f, version & 0x7f
    year, month = 2000 + (patch >> 4), patch & 0xf
    return f"{a}.{b}.{c}", f"{year:04d}-{month:02d}-01"


def parse_vendor_boot(vendor_boot):
    if vendor_boot[:8] != VENDOR_BOOT_MAGIC:
        die("vendor_boot.img: bad magic")
    header_version, page_size = struct.unpack_from("<2I", vendor_boot, 8)
    if header_version != 4:
        die(f"vendor_boot.img: unsupported header version {header_version}")
    vendor_ramdisk_size = struct.unpack_from("<I", vendor_boot, 24)[0]
    off = 28 + 2048  # after kernel/ramdisk addrs + cmdline
    off += 4 + 16  # tags_addr + name
    header_size, dtb_size = struct.unpack_from("<2I", vendor_boot, off)
    off += 8 + 8  # + dtb_addr
    table_size, table_entry_num, table_entry_size, _bootconfig_size = \
        struct.unpack_from("<4I", vendor_boot, off)

    ramdisk_off = align(header_size, page_size)
    dtb_off = ramdisk_off + align(vendor_ramdisk_size, page_size)
    table_off = dtb_off + align(dtb_size, page_size)

    dtb = vendor_boot[dtb_off:dtb_off + dtb_size]
    fragments = []
    for i in range(table_entry_num):
        entry = vendor_boot[table_off + i * table_entry_size:
                            table_off + (i + 1) * table_entry_size]
        size, offset, ramdisk_type = struct.unpack_from("<3I", entry, 0)
        name = entry[12:44].split(b"\0")[0].decode()
        data = vendor_boot[ramdisk_off + offset:ramdisk_off + offset + size]
        fragments.append((ramdisk_type, name, data))
    return dtb, fragments


def decompress(data):
    if data[:4] == LZ4_LEGACY_MAGIC:
        return subprocess.run(["lz4", "-dc"], input=data, stdout=subprocess.PIPE,
                              check=True).stdout
    if data[:2] == GZIP_MAGIC:
        return gzip.decompress(data)
    return data


def cpio_entries(data):
    """Yield (name, mode, content) for a newc cpio archive."""
    off = 0
    while off + 110 <= len(data):
        if data[off:off + 6] not in (b"070701", b"070702"):
            die(f"cpio: bad magic at {off}")
        fields = [int(data[off + 6 + i * 8:off + 14 + i * 8], 16) for i in range(13)]
        mode, filesize, namesize = fields[1], fields[6], fields[11]
        name_off = off + 110
        name = data[name_off:name_off + namesize - 1].decode()
        file_off = align(name_off + namesize, 4)
        if name == "TRAILER!!!":
            return
        yield name, mode, data[file_off:file_off + filesize]
        off = align(file_off + filesize, 4)


def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--boot", required=True)
    parser.add_argument("--vendor-boot", required=True)
    parser.add_argument("--device-dir", required=True)
    args = parser.parse_args()

    device_dir = args.device_dir
    root = os.path.join(device_dir, "recovery", "root")
    modules_dir = os.path.join(root, "lib", "modules")
    firmware_dir = os.path.join(root, "vendor", "firmware")
    for path in (modules_dir, firmware_dir):
        shutil.rmtree(path, ignore_errors=True)

    with open(args.boot, "rb") as f:
        kernel, os_version = extract_kernel(f.read())
    write_file(os.path.join(device_dir, "prebuilt", "kernel"), kernel)
    print(f"kernel: {len(kernel)} bytes")

    # KeyMint binds keys to the booted image's OS version and patch level, so the
    # recovery has to report exactly what the firmware's boot.img does
    version, patch = decode_os_version(os_version)
    write_file(os.path.join(device_dir, "prebuilt", "bootimg_version.mk"),
               f"BOARD_MKBOOTIMG_ARGS += --os_version {version} --os_patch_level {patch}\n".encode())
    print(f"boot.img os_version {version}, os_patch_level {patch}")

    with open(args.vendor_boot, "rb") as f:
        dtb, fragments = parse_vendor_boot(f.read())
    write_file(os.path.join(device_dir, "prebuilt", "dtb.img"), dtb)
    print(f"dtb: {len(dtb)} bytes")

    modules = 0
    firmware = 0
    for ramdisk_type, name, data in fragments:
        for path, mode, content in cpio_entries(decompress(data)):
            if not (mode & 0o170000) == 0o100000:  # regular files only
                continue
            if ramdisk_type == VENDOR_RAMDISK_TYPE_DLKM and path.startswith("lib/modules/"):
                write_file(os.path.join(root, path), content)
                modules += path.endswith(".ko")
            elif ramdisk_type == VENDOR_RAMDISK_TYPE_PLATFORM and path.startswith("vendor/firmware/"):
                write_file(os.path.join(root, path), content)
                firmware += 1
        print(f"vendor ramdisk '{name or 'platform'}' (type {ramdisk_type}) processed")

    load = os.path.join(modules_dir, "modules.load")
    if not modules or not os.path.exists(load):
        die("no kernel modules found in vendor_boot")
    # First stage init prefers modules.load.recovery in recovery mode
    shutil.copyfile(load, os.path.join(modules_dir, "modules.load.recovery"))
    print(f"modules: {modules}, firmware files: {firmware}")


if __name__ == "__main__":
    main()

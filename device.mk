#
# Copyright (C) 2026 The Android Open Source Project
#
# SPDX-License-Identifier: Apache-2.0
#

LOCAL_PATH := device/samsung/a14

# Dynamic partitions
PRODUCT_USE_DYNAMIC_PARTITIONS := true

# Exynos watchdog (s3c2410_wdt) is armed once its module loads;
# recovery must keep feeding it or the device reboots.
PRODUCT_PACKAGES += \
    watchdogd.recovery

# /data decryption; crash_dump installs as crash_dump64, without it an abort in
# the recovery binary leaves nothing but "Fatal signal 6" in the log
PRODUCT_PACKAGES += \
    apexservice_stub \
    ce_unlock \
    crash_dump \
    gk_verify

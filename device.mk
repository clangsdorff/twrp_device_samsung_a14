#
# Copyright (C) 2026 The Android Open Source Project
#
# SPDX-License-Identifier: Apache-2.0
#

LOCAL_PATH := device/samsung/a14

# API levels
PRODUCT_SHIPPING_API_LEVEL := 33

# Dynamic partitions
PRODUCT_USE_DYNAMIC_PARTITIONS := true

# Exynos watchdog (s3c2410_wdt) is armed once its module loads;
# recovery must keep feeding it or the device reboots.
PRODUCT_PACKAGES += \
    watchdogd.recovery

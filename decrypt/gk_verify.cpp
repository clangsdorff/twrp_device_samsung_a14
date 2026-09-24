/*
 * Verifies a stretched credential against the enrolled gatekeeper handle and prints the
 * resulting hardware auth token as hex.
 *
 * Separate from langsdorff_decrypt because the only gatekeeper on this device is HIDL 1.0, which
 * lives on the recovery's own hwservicemanager and needs the recovery's libhidlbase.
 * langsdorff_decrypt runs under the firmware bootstrap linker and cannot load both.
 *
 * usage: gk_verify <uid> <enrolled_handle_hex> <provided_password_hex>
 */

#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using android::sp;
using android::hardware::hidl_vec;
using android::hardware::gatekeeper::V1_0::GatekeeperResponse;
using android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
using android::hardware::gatekeeper::V1_0::IGatekeeper;

static bool unhex(const char* s, std::vector<uint8_t>* out) {
    size_t n = strlen(s);
    if (n % 2 != 0) return false;
    out->clear();
    out->reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < n; i += 2) {
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: gk_verify <uid> <handle_hex> <password_hex>\n");
        return 22;
    }
    std::vector<uint8_t> handle, password;
    if (!unhex(argv[2], &handle) || !unhex(argv[3], &password)) {
        fprintf(stderr, "bad hex\n");
        return 22;
    }

    sp<IGatekeeper> gk = IGatekeeper::getService();
    if (gk == nullptr) {
        fprintf(stderr, "IGatekeeper/default not found\n");
        return 1;
    }

    GatekeeperResponse rsp;
    auto ret = gk->verify(static_cast<uint32_t>(strtoul(argv[1], nullptr, 10)), 0,
                          hidl_vec<uint8_t>(handle), hidl_vec<uint8_t>(password),
                          [&rsp](const GatekeeperResponse& r) { rsp = r; });
    if (!ret.isOk()) {
        fprintf(stderr, "verify transport error: %s\n", ret.description().c_str());
        return 1;
    }
    if (rsp.code != GatekeeperStatusCode::STATUS_OK) {
        fprintf(stderr, "verify rejected: code=%d timeout=%u\n", static_cast<int>(rsp.code),
                rsp.timeout);
        return 2;
    }

    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(rsp.data.size() * 2);
    for (size_t i = 0; i < rsp.data.size(); i++) {
        out.push_back(d[rsp.data[i] >> 4]);
        out.push_back(d[rsp.data[i] & 0xf]);
    }
    printf("%s\n", out.c_str());
    return 0;
}

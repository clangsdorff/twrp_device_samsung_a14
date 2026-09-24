/*
 * Recovers the user-0 synthetic password and unlocks the CE storage layer. The metadata
 * and DE layers are already up by the time this runs (vdc cryptfs mountFstab,
 * enablefilecrypto, init_user0); vdc has no command for CE.
 *
 * Derived from de_keyinstall.cpp in TeamWin/android_device_samsung_pa3q, cut down for a
 * device with no weaver and no hardware-wrapped keys.
 *
 * LockSettingsService chain:
 *   stretchedLskf   = "default-password" padded to 32B, or scrypt(credential, salt from .pwd)
 *   protectorSecret = stretchedLskf || SHA512(pad128("secdiscardable-transform") || .secdis)
 *   sp              = GCM(GCM(.spblob[2:], keystore key synthetic_password_<handle>),
 *                          SHA512(pad128("application-id") || protectorSecret)[:32])
 *   secret          = SP800-108(sp, "fbe-key", "android-synthetic-password-personalization-context")
 *
 * Runs through the firmware bootstrap linker, because KeyMint lives on the firmware's
 * servicemanager. The KeyMint stubs are static so only libbinder_ndk, libcrypto and
 * libsqlite are resolved at runtime.
 */

#define LOG_TAG "ce_unlock"

#include <aidl/android/hardware/security/keymint/BeginResult.h>
#include <aidl/android/hardware/security/keymint/BlockMode.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthenticatorType.h>
#include <aidl/android/hardware/security/keymint/IKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/IKeyMintOperation.h>
#include <aidl/android/hardware/security/keymint/KeyParameter.h>
#include <aidl/android/hardware/security/keymint/KeyParameterValue.h>
#include <aidl/android/hardware/security/keymint/KeyPurpose.h>
#include <aidl/android/hardware/security/keymint/PaddingMode.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/binder_parcel.h>
#include <android/binder_process.h>
#include <android/binder_status.h>
#include <android/log.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include <endian.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

using aidl::android::hardware::security::keymint::BeginResult;
using aidl::android::hardware::security::keymint::BlockMode;
using aidl::android::hardware::security::keymint::HardwareAuthenticatorType;
using aidl::android::hardware::security::keymint::HardwareAuthToken;
using aidl::android::hardware::security::keymint::IKeyMintDevice;
using aidl::android::hardware::security::keymint::IKeyMintOperation;
using aidl::android::hardware::security::keymint::KeyParameter;
using aidl::android::hardware::security::keymint::KeyParameterValue;
using aidl::android::hardware::security::keymint::KeyPurpose;
using aidl::android::hardware::security::keymint::PaddingMode;
using aidl::android::hardware::security::keymint::Tag;

#define LINE(...)                                                    \
    do {                                                             \
        fprintf(stdout, __VA_ARGS__);                                \
        fprintf(stdout, "\n");                                       \
        fflush(stdout);                                              \
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
    } while (0)

#define KEY_SPEC_TYPE_IDENTIFIER 2u

struct fscrypt_key_specifier_local {
    __u32 type;
    __u32 __reserved;
    union {
        __u8 __reserved2[32];
        __u8 descriptor[8];
        __u8 identifier[16];
    } u;
};
struct fscrypt_add_key_arg_local {
    struct fscrypt_key_specifier_local key_spec;
    __u32 raw_size;
    __u32 key_id;
    __u32 __reserved[8];
    __u8 raw[];
};
#define FS_IOC_ADD_ENCRYPTION_KEY_LOCAL _IOWR('f', 23, struct fscrypt_add_key_arg_local)

namespace {

const int kGcmNonceLen = 12;
const int kHashPersonLen = 128;  // SHA512_CBLOCK

const char* kSpblobDir = "/data/system_de/0/spblob/";
const char* kCeKeyFile = "/data/misc/vold/user_keys/ce/0/current/encrypted_key";

bool readFile(const std::string& path, std::vector<uint8_t>* out) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out->clear();
    uint8_t buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) out->insert(out->end(), buf, buf + n);
    close(fd);
    return n >= 0;
}

bool unhex(const std::string& s, std::vector<uint8_t>* out) {
    if (s.size() % 2 != 0) return false;
    out->clear();
    out->reserve(s.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0xf]);
    }
    return s;
}

// SyntheticPasswordCrypto.personalisedHash
std::vector<uint8_t> personalizedHash(const std::string& personalization,
                                      const std::vector<uint8_t>& data) {
    SHA512_CTX c;
    SHA512_Init(&c);
    char person[kHashPersonLen];
    memset(person, 0, sizeof(person));
    memcpy(person, personalization.data(),
           std::min(personalization.size(), static_cast<size_t>(kHashPersonLen)));
    SHA512_Update(&c, person, sizeof(person));
    SHA512_Update(&c, data.data(), data.size());
    std::vector<uint8_t> out(SHA512_DIGEST_LENGTH);
    SHA512_Final(out.data(), &c);
    return out;
}

// sp-handle is a signed int64 decimal; the spblob filenames use its unsigned hex form.
bool getCurrentProtectorHandle(std::string* handleHex) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2("file:/data/system/locksettings.db?mode=ro&immutable=1", &db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_stmt* stmt = nullptr;
    bool ok = false;
    if (sqlite3_prepare_v2(db, "SELECT value FROM locksettings WHERE name='sp-handle' AND user=0",
                           -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        const char* v = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (v != nullptr) {
            uint64_t h = static_cast<uint64_t>(strtoll(v, nullptr, 10));
            char buf[24];
            snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
            *handleHex = buf;
            ok = true;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok;
}

bool getSpKeystoreBlob(const std::string& handleHex, std::vector<uint8_t>* blob) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2("file:/data/misc/keystore/persistent.sqlite?mode=ro&immutable=1", &db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    const char* sql =
            "SELECT b.blob FROM blobentry b JOIN keyentry k ON b.keyentryid=k.id "
            "WHERE k.alias=? AND b.subcomponent_type=0";
    // The alias is formatted with %x, so a handle with a leading zero nibble is unpadded.
    std::string trimmed = handleHex;
    trimmed.erase(0, std::min(trimmed.find_first_not_of('0'), trimmed.size() - 1));
    bool ok = false;
    for (const std::string& h : {handleHex, trimmed}) {
        std::string alias = "synthetic_password_" + h;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK &&
            sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_ROW) {
            const uint8_t* p = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
            int n = sqlite3_column_bytes(stmt, 0);
            if (p != nullptr && n > 0) {
                blob->assign(p, p + n);
                ok = true;
            }
        }
        sqlite3_finalize(stmt);
        if (ok) break;
    }
    sqlite3_close(db);
    return ok;
}

std::vector<uint8_t> emptyStretchedLskf() {
    std::vector<uint8_t> s(32, 0);
    const char* dp = "default-password";
    memcpy(s.data(), dp, strlen(dp));
    return s;
}

enum { CRED_NONE = -1, CRED_PATTERN = 1, CRED_PIN = 3, CRED_PASSWORD = 4 };

// PasswordData, big-endian: int credentialType; byte logN; byte logR; byte logP;
// int saltLength; byte[] salt; int gatekeeperHandleLength; byte[] gatekeeperHandle.
bool readPasswordData(const std::string& handleHex, int32_t* credType, int* logN, int* logR,
                      int* logP, std::vector<uint8_t>* salt, std::vector<uint8_t>* gkHandle) {
    std::vector<uint8_t> d;
    if (!readFile(std::string(kSpblobDir) + handleHex + ".pwd", &d) || d.size() < 11) return false;
    auto be32 = [&](size_t o) -> int32_t {
        return (int32_t)(((uint32_t)d[o] << 24) | ((uint32_t)d[o + 1] << 16) |
                         ((uint32_t)d[o + 2] << 8) | (uint32_t)d[o + 3]);
    };
    *credType = be32(0);
    *logN = d[4];
    *logR = d[5];
    *logP = d[6];
    int32_t saltLen = be32(7);
    if (saltLen < 0 || (size_t)(11 + saltLen) > d.size()) return false;
    salt->assign(d.begin() + 11, d.begin() + 11 + saltLen);
    size_t o = 11 + saltLen;
    if (o + 4 <= d.size()) {
        int32_t hLen = be32(o);
        if (hLen > 0 && o + 4 + hLen <= d.size())
            gkHandle->assign(d.begin() + o + 4, d.begin() + o + 4 + hLen);
    }
    return true;
}

bool scryptStretch(const std::string& credential, const std::vector<uint8_t>& salt, int logN,
                   int logR, int logP, std::vector<uint8_t>* out) {
    out->assign(32, 0);
    uint64_t N = 1ull << logN, r = 1ull << logR, p = 1ull << logP;
    return EVP_PBE_scrypt(credential.data(), credential.size(), salt.data(), salt.size(), N, r, p,
                          64ull * 1024 * 1024, out->data(), 32) == 1;
}

bool swGcmDecrypt(const std::vector<uint8_t>& key32, const std::vector<uint8_t>& iv12,
                  const std::vector<uint8_t>& ctAndTag, std::vector<uint8_t>* out) {
    if (key32.size() != 32 || iv12.size() != 12 || ctAndTag.size() < 16) return false;
    size_t ctLen = ctAndTag.size() - 16;
    const uint8_t* tag = ctAndTag.data() + ctLen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    out->assign(ctLen, 0);
    int outl = 0, finl = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), iv12.data()) == 1 &&
              EVP_DecryptUpdate(ctx, out->data(), &outl, ctAndTag.data(),
                                static_cast<int>(ctLen)) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) == 1 &&
              EVP_DecryptFinal_ex(ctx, out->data() + outl, &finl) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (ok) out->resize(outl + finl);
    return ok;
}

// SP800-108 counter mode, HmacSHA256, one 32B block, as SyntheticPassword.deriveSubkey uses it.
std::vector<uint8_t> sp800Derive(const std::vector<uint8_t>& key, const std::string& label,
                                 const std::string& context) {
    std::vector<uint8_t> fixed;
    auto be32 = [&](uint32_t v) {
        fixed.push_back((v >> 24) & 0xff);
        fixed.push_back((v >> 16) & 0xff);
        fixed.push_back((v >> 8) & 0xff);
        fixed.push_back(v & 0xff);
    };
    be32(1);
    fixed.insert(fixed.end(), label.begin(), label.end());
    fixed.push_back(0);
    fixed.insert(fixed.end(), context.begin(), context.end());
    be32(static_cast<uint32_t>(context.size()) * 8);
    be32(256);
    uint8_t mac[32];
    unsigned int maclen = sizeof(mac);
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), fixed.data(), fixed.size(), mac,
         &maclen);
    return std::vector<uint8_t>(mac, mac + maclen);
}

KeyParameter kpEnum(Tag tag, KeyParameterValue v) { return KeyParameter{tag, std::move(v)}; }

void logStatus(const char* what, const ::ndk::ScopedAStatus& st) {
    LINE("  %s: ex=%d serviceSpecific=%d msg=%s", what, st.getExceptionCode(),
         st.getServiceSpecificError(), st.getMessage() ? st.getMessage() : "(none)");
}

bool kmGcmDecrypt(const std::shared_ptr<IKeyMintDevice>& km, std::vector<uint8_t> keyblob,
                  const std::vector<uint8_t>& encryptedKey,
                  const std::optional<HardwareAuthToken>& authToken, std::vector<uint8_t>* out) {
    if (static_cast<int>(encryptedKey.size()) <= kGcmNonceLen + 16) {
        LINE("  gcm blob too small (%zuB)", encryptedKey.size());
        return false;
    }
    std::vector<uint8_t> nonce(encryptedKey.begin(), encryptedKey.begin() + kGcmNonceLen);
    std::vector<uint8_t> body(encryptedKey.begin() + kGcmNonceLen, encryptedKey.end());

    std::vector<KeyParameter> params;
    params.push_back(kpEnum(Tag::BLOCK_MODE,
                            KeyParameterValue::make<KeyParameterValue::blockMode>(BlockMode::GCM)));
    params.push_back(kpEnum(Tag::PADDING, KeyParameterValue::make<KeyParameterValue::paddingMode>(
                                                  PaddingMode::NONE)));
    params.push_back(
            kpEnum(Tag::MAC_LENGTH, KeyParameterValue::make<KeyParameterValue::integer>(128)));
    params.push_back(kpEnum(Tag::NONCE, KeyParameterValue::make<KeyParameterValue::blob>(nonce)));

    BeginResult begun;
    auto st = km->begin(KeyPurpose::DECRYPT, keyblob, params, authToken, &begun);
    if (st.getServiceSpecificError() == -62 /* KEY_REQUIRES_UPGRADE */) {
        std::vector<uint8_t> upgraded;
        auto ust = km->upgradeKey(keyblob, {}, &upgraded);
        if (!ust.isOk()) {
            logStatus("upgradeKey", ust);
            return false;
        }
        keyblob = std::move(upgraded);
        st = km->begin(KeyPurpose::DECRYPT, keyblob, params, authToken, &begun);
    }
    if (!st.isOk() || begun.operation == nullptr) {
        logStatus("begin(DECRYPT)", st);
        return false;
    }

    std::vector<uint8_t> partial;
    st = begun.operation->update(body, authToken, std::nullopt, &partial);
    if (!st.isOk()) {
        logStatus("operation.update", st);
        begun.operation->abort();
        return false;
    }
    std::vector<uint8_t> tail;
    st = begun.operation->finish(std::nullopt, std::nullopt, authToken, std::nullopt, std::nullopt,
                                 &tail);
    if (!st.isOk()) {
        logStatus("operation.finish", st);
        return false;
    }
    out->clear();
    out->insert(out->end(), partial.begin(), partial.end());
    out->insert(out->end(), tail.begin(), tail.end());
    return true;
}

bool unwrapSyntheticPassword(const std::shared_ptr<IKeyMintDevice>& km,
                             const std::string& handleHex,
                             const std::vector<uint8_t>& stretchedLskf,
                             const std::optional<HardwareAuthToken>& authToken,
                             std::vector<uint8_t>* sp) {
    std::vector<uint8_t> spKeyBlob;
    if (!getSpKeystoreBlob(handleHex, &spKeyBlob) || spKeyBlob.empty()) {
        LINE("  keystore key synthetic_password_%s not found in persistent.sqlite",
             handleHex.c_str());
        return false;
    }
    std::vector<uint8_t> spblob;
    if (!readFile(std::string(kSpblobDir) + handleHex + ".spblob", &spblob) || spblob.size() < 3) {
        LINE("  %s%s.spblob missing or short", kSpblobDir, handleHex.c_str());
        return false;
    }
    LINE("  spblob %zuB version=%d protectorType=%d, keystore keyblob %zuB", spblob.size(),
         spblob[0], spblob[1], spKeyBlob.size());

    std::vector<uint8_t> secdis;
    if (!readFile(std::string(kSpblobDir) + handleHex + ".secdis", &secdis)) {
        LINE("  %s%s.secdis missing", kSpblobDir, handleHex.c_str());
        return false;
    }
    std::vector<uint8_t> protectorSecret = stretchedLskf;
    std::vector<uint8_t> sdh = personalizedHash("secdiscardable-transform", secdis);
    protectorSecret.insert(protectorSecret.end(), sdh.begin(), sdh.end());

    std::vector<uint8_t> mContent(spblob.begin() + 2, spblob.end());
    std::vector<uint8_t> intermediate;
    if (!kmGcmDecrypt(km, spKeyBlob, mContent, authToken, &intermediate)) {
        LINE("  spblob outer layer decrypt failed");
        return false;
    }
    if (intermediate.size() < kGcmNonceLen + 16) {
        LINE("  spblob outer result too small for the inner layer");
        return false;
    }

    std::vector<uint8_t> innerKey = personalizedHash("application-id", protectorSecret);
    innerKey.resize(32);
    std::vector<uint8_t> iv(intermediate.begin(), intermediate.begin() + kGcmNonceLen);
    std::vector<uint8_t> ct(intermediate.begin() + kGcmNonceLen, intermediate.end());
    if (!swGcmDecrypt(innerKey, iv, ct, sp)) {
        LINE("  spblob inner layer decrypt failed, wrong credential");
        return false;
    }
    LINE("  synthetic password recovered: %zuB", sp->size());
    return true;
}

// hw_auth_token_t: version, then challenge/userId/authenticatorId in host order and
// authenticatorType/timestamp in network order, then a 32 byte hmac.
bool parseAuthToken(const std::vector<uint8_t>& b, HardwareAuthToken* out) {
    if (b.size() != 69 || b[0] != 0) return false;
    uint64_t u64;
    uint32_t u32;
    memcpy(&u64, b.data() + 1, 8);
    out->challenge = static_cast<int64_t>(u64);
    memcpy(&u64, b.data() + 9, 8);
    out->userId = static_cast<int64_t>(u64);
    memcpy(&u64, b.data() + 17, 8);
    out->authenticatorId = static_cast<int64_t>(u64);
    memcpy(&u32, b.data() + 25, 4);
    out->authenticatorType = static_cast<HardwareAuthenticatorType>(be32toh(u32));
    memcpy(&u64, b.data() + 29, 8);
    out->timestamp.milliSeconds = static_cast<int64_t>(be64toh(u64));
    out->mac.assign(b.begin() + 37, b.end());
    return true;
}

// The gatekeeper HAL is HIDL only and lives on the recovery's hwservicemanager, so the
// verify runs in a helper that is not under the firmware linker.
bool gatekeeperVerify(const std::vector<uint8_t>& gkHandle,
                      const std::vector<uint8_t>& stretchedLskf, HardwareAuthToken* out) {
    std::vector<uint8_t> gkInput = personalizedHash("user-gk-authentication", stretchedLskf);
    std::string cmd = "/system/bin/gk_verify 100000 " + hex(gkHandle.data(), gkHandle.size()) + " " +
                      hex(gkInput.data(), gkInput.size());
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_PRELOAD");
    FILE* f = popen(cmd.c_str(), "r");
    if (f == nullptr) {
        LINE("  cannot run gk_verify");
        return false;
    }
    char buf[256] = {0};
    if (fgets(buf, sizeof(buf), f) == nullptr) buf[0] = 0;
    int rc = pclose(f);
    std::string tokenHex(buf);
    while (!tokenHex.empty() && (tokenHex.back() == '\n' || tokenHex.back() == '\r'))
        tokenHex.pop_back();
    if (rc != 0 || tokenHex.empty()) {
        LINE("  gatekeeper rejected the credential (gk_verify exit %d)", rc);
        return false;
    }
    std::vector<uint8_t> token;
    if (!unhex(tokenHex, &token) || !parseAuthToken(token, out)) {
        LINE("  gatekeeper returned an auth token of %zu bytes, cannot parse", token.size());
        return false;
    }
    LINE("  gatekeeper accepted, auth token sid=%lld type=%d", (long long)out->userId,
         static_cast<int>(out->authenticatorType));
    return true;
}

void* VoldOnCreate(void* args) { return args; }
void VoldOnDestroy(void* /*userData*/) {}
binder_status_t VoldOnTransact(AIBinder* /*b*/, transaction_code_t /*code*/, const AParcel* /*in*/,
                               AParcel* /*out*/) {
    return STATUS_UNKNOWN_TRANSACTION;
}

bool writeUnlockArgs(AIBinder* vold, int userId, const std::vector<uint8_t>& secret, AParcel** in) {
    if (AIBinder_prepareTransaction(vold, in) != STATUS_OK) return false;
    if (AParcel_writeInt32(*in, userId) != STATUS_OK ||
        AParcel_writeByteArray(*in, reinterpret_cast<const int8_t*>(secret.data()),
                               static_cast<int32_t>(secret.size())) != STATUS_OK) {
        AParcel_delete(*in);
        return false;
    }
    return true;
}

// IVold.unlockCeStorage(int userId, in byte[] secret). vdc has no command for it; the
// transaction code comes from disassembling this firmware's own vdc.
bool voldUnlockCe(int userId, const std::vector<uint8_t>& secret) {
    ::ndk::SpAIBinder vb(AServiceManager_getService("vold"));
    AIBinder* vold = vb.get();
    if (vold == nullptr) {
        LINE("  vold service not found");
        return false;
    }
    AIBinder_Class* clazz =
            AIBinder_Class_define("android.os.IVold", VoldOnCreate, VoldOnDestroy, VoldOnTransact);
    if (!AIBinder_associateClass(vold, clazz)) {
        LINE("  vold binder is not android.os.IVold");
        return false;
    }
    AParcel* in = nullptr;
    if (!writeUnlockArgs(vold, userId, secret, &in)) return false;
    AParcel* out = nullptr;
    binder_status_t t = AIBinder_transact(vold, 57, &in, &out, 0x20 /* FLAG_CLEAR_BUF */);
    if (t == STATUS_BAD_VALUE) {
        if (!writeUnlockArgs(vold, userId, secret, &in)) return false;
        t = AIBinder_transact(vold, 57, &in, &out, 0);
    }
    if (t != STATUS_OK) {
        LINE("  unlockCeStorage transport error %d", t);
        return false;
    }
    AStatus* st = nullptr;
    bool ok = false;
    if (AParcel_readStatusHeader(out, &st) == STATUS_OK && st != nullptr) {
        ok = AStatus_isOk(st);
        if (!ok)
            LINE("  unlockCeStorage rejected: ex=%d serviceSpecific=%d",
                 AStatus_getExceptionCode(st), AStatus_getServiceSpecificError(st));
        AStatus_delete(st);
    }
    AParcel_delete(out);
    return ok;
}

// The CE directory carries no secdiscardable, so the key encryption key comes from the
// fbe-key secret alone.
bool installCeKeyDirect(const std::vector<uint8_t>& fbeKey) {
    std::vector<uint8_t> encKey;
    if (!readFile(kCeKeyFile, &encKey) || encKey.size() < kGcmNonceLen + 16) {
        LINE("  %s missing or short", kCeKeyFile);
        return false;
    }
    std::vector<uint8_t> kek =
            personalizedHash("Android key wrapping key generation SHA512", fbeKey);
    kek.resize(32);
    std::vector<uint8_t> iv(encKey.begin(), encKey.begin() + kGcmNonceLen);
    std::vector<uint8_t> ct(encKey.begin() + kGcmNonceLen, encKey.end());
    std::vector<uint8_t> ceKey;
    if (!swGcmDecrypt(kek, iv, ct, &ceKey)) {
        LINE("  CE encrypted_key decrypt failed");
        return false;
    }

    int dfd = open("/data", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        LINE("  open(/data) failed: %s", strerror(errno));
        return false;
    }
    std::vector<uint8_t> argBuf(sizeof(struct fscrypt_add_key_arg_local) + ceKey.size(), 0);
    auto* arg = reinterpret_cast<struct fscrypt_add_key_arg_local*>(argBuf.data());
    arg->key_spec.type = KEY_SPEC_TYPE_IDENTIFIER;
    arg->raw_size = static_cast<__u32>(ceKey.size());
    memcpy(arg->raw, ceKey.data(), ceKey.size());
    int rc = ioctl(dfd, FS_IOC_ADD_ENCRYPTION_KEY_LOCAL, arg);
    close(dfd);
    if (rc != 0) {
        LINE("  FS_IOC_ADD_ENCRYPTION_KEY failed: %s", strerror(errno));
        return false;
    }
    LINE("  CE key installed, kernel id=%s", hex(arg->key_spec.u.identifier, 16).c_str());
    return true;
}

bool writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    ssize_t w = write(fd, data.data(), data.size());
    close(fd);
    return w == static_cast<ssize_t>(data.size());
}

bool dirReadable(const char* path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    close(fd);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::string credential = (argc > 1 && argv[1] != nullptr) ? std::string(argv[1]) : std::string();
    LINE("===== ce_unlock start =====");

    if (!dirReadable("/data/system_de/0")) {
        LINE("FATAL: /data/system_de/0 is not readable, the DE layer is still locked");
        return 1;
    }

    ABinderProcess_setThreadPoolMaxThreadCount(1);
    ABinderProcess_startThreadPool();
    ::ndk::SpAIBinder binder(
            AServiceManager_getService("android.hardware.security.keymint.IKeyMintDevice/default"));
    std::shared_ptr<IKeyMintDevice> km = IKeyMintDevice::fromBinder(binder);
    if (km == nullptr) {
        LINE("FATAL: IKeyMintDevice/default not found");
        return 1;
    }
    int32_t kmVer = 0;
    km->getInterfaceVersion(&kmVer);
    LINE("KeyMint interface V%d", kmVer);

    std::string handle;
    if (!getCurrentProtectorHandle(&handle)) {
        LINE("FATAL: no sp-handle for user 0 in locksettings.db");
        return 1;
    }
    LINE("protector %s", handle.c_str());

    std::vector<uint8_t> stretchedLskf;
    int32_t credType = CRED_NONE;
    int lN = 0, lR = 0, lP = 0;
    std::vector<uint8_t> salt, gkHandle;
    if (!readPasswordData(handle, &credType, &lN, &lR, &lP, &salt, &gkHandle) ||
        credType == CRED_NONE) {
        stretchedLskf = emptyStretchedLskf();
        LINE("credential: none");
    } else if (credential.empty()) {
        // the recovery picks its input page from this: 2 pattern, 3 pin, anything else a keyboard
        int pwtype = credType == CRED_PATTERN ? 2 : (credType == CRED_PIN ? 3 : 0);
        char b[8];
        int n = snprintf(b, sizeof(b), "%d", pwtype);
        writeFile("/tmp/.ce_pwtype", std::vector<uint8_t>(b, b + n));
        // a pattern is just the touched cells as digits, row major, top left is 1
        LINE("FATAL: the protector needs a credential (type=%d), pass it as an argument%s",
             credType, credType == CRED_PATTERN ? " (the pattern cells as digits 1-9)" : "");
        return 2;
    } else if (!scryptStretch(credential, salt, lN, lR, lP, &stretchedLskf)) {
        LINE("FATAL: scrypt of the credential failed");
        return 2;
    } else {
        LINE("credential type=%d scrypt(N=%d,r=%d,p=%d)", credType, 1 << lN, 1 << lR, 1 << lP);
    }

    // with a real credential the protector key is bound to the secure user id, so KeyMint
    // answers KEY_USER_NOT_AUTHENTICATED until it is handed a fresh gatekeeper token
    std::optional<HardwareAuthToken> authToken;
    if (credType != CRED_NONE) {
        if (gkHandle.empty()) {
            LINE("FATAL: no gatekeeper handle in the protector password data");
            return 2;
        }
        HardwareAuthToken hat;
        if (!gatekeeperVerify(gkHandle, stretchedLskf, &hat)) {
            LINE("FATAL: gatekeeper did not accept the credential");
            return 2;
        }
        authToken = hat;
    }

    std::vector<uint8_t> sp;
    if (!unwrapSyntheticPassword(km, handle, stretchedLskf, authToken, &sp) || sp.empty()) {
        LINE("FATAL: could not recover the synthetic password");
        return 3;
    }

    std::vector<uint8_t> secret =
            sp800Derive(sp, "fbe-key", "android-synthetic-password-personalization-context");

    if (voldUnlockCe(0, secret)) {
        LINE("vold unlockCeStorage accepted");
    } else if (!installCeKeyDirect(secret)) {
        LINE("FATAL: CE key install failed");
        return 4;
    }

    bool open0 = dirReadable("/data/user/0");
    LINE("/data/data %s, /data/user/0 %s", dirReadable("/data/data") ? "readable" : "locked",
         open0 ? "readable" : "locked");
    LINE("===== ce_unlock done =====");
    return open0 ? 0 : 5;
}

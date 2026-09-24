// Unlocks /data without the firmware vold: key files are only ever read, KeyMint key
// upgrades are refused instead of performed, and nothing is deleted from KeyMint.

#define LOG_TAG "langsdorff_decrypt"

#include <aidl/android/hardware/security/keymint/BeginResult.h>
#include <aidl/android/hardware/security/keymint/BlockMode.h>
#include <aidl/android/hardware/security/keymint/ErrorCode.h>
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
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/log.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include <endian.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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
using aidl::android::hardware::security::keymint::ErrorCode;
using aidl::android::hardware::security::keymint::HardwareAuthenticatorType;
using aidl::android::hardware::security::keymint::HardwareAuthToken;
using aidl::android::hardware::security::keymint::IKeyMintDevice;
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

// Older uapi headers in the 12.1 tree predate the v2 key ioctls.
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

const size_t kGcmNonceLen = 12;
const size_t kGcmTagLen = 16;
const size_t kHashPersonLen = 128;  // SHA512_CBLOCK

// userdata stays mounted here for as long as the recovery runs, whatever it does to /data
#define DATA_ROOT "/tmp/.userdata"
const char* kMetadataKeyDir = "/metadata/vold/metadata_encryption/key";
const char* kSystemDeKeyDir = DATA_ROOT "/unencrypted/key";
const char* kUser0DeKeyDir = DATA_ROOT "/misc/vold/user_keys/de/0";
const char* kUser0CeKeyDir = DATA_ROOT "/misc/vold/user_keys/ce/0/current";
const char* kSpblobDir = DATA_ROOT "/system_de/0/spblob/";
const char* kDmName = "userdata";

enum Exit { OK = 0, FAIL = 1, NEED_CREDENTIAL = 2, BAD_CREDENTIAL = 3, NEEDS_UPGRADE = 4 };

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

bool exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
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

bool unhex(const std::string& s, std::vector<uint8_t>* out) {
    if (s.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out->clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

// vold hashWithPrefix and SyntheticPasswordCrypto.personalizedHash are the same construction
std::vector<uint8_t> personalizedHash(const std::string& personalization,
                                      const std::vector<uint8_t>& data) {
    SHA512_CTX c;
    SHA512_Init(&c);
    char person[kHashPersonLen];
    memset(person, 0, sizeof(person));
    memcpy(person, personalization.data(), std::min(personalization.size(), kHashPersonLen));
    SHA512_Update(&c, person, sizeof(person));
    SHA512_Update(&c, data.data(), data.size());
    std::vector<uint8_t> out(SHA512_DIGEST_LENGTH);
    SHA512_Final(out.data(), &c);
    return out;
}

bool swGcmDecrypt(const std::vector<uint8_t>& key32, const std::vector<uint8_t>& nonceCtTag,
                  std::vector<uint8_t>* out) {
    if (key32.size() != 32 || nonceCtTag.size() < kGcmNonceLen + kGcmTagLen) return false;
    const uint8_t* iv = nonceCtTag.data();
    const uint8_t* ct = iv + kGcmNonceLen;
    size_t ctLen = nonceCtTag.size() - kGcmNonceLen - kGcmTagLen;
    const uint8_t* tag = ct + ctLen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    out->assign(ctLen, 0);
    int outl = 0, finl = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmNonceLen, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), iv) == 1 &&
              EVP_DecryptUpdate(ctx, out->data(), &outl, ct, static_cast<int>(ctLen)) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kGcmTagLen,
                                  const_cast<uint8_t*>(tag)) == 1 &&
              EVP_DecryptFinal_ex(ctx, out->data() + outl, &finl) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (ok) out->resize(outl + finl);
    return ok;
}

// SP800-108 counter mode, HmacSHA256, one 32B block, as SyntheticPassword.deriveSubkey uses it
std::vector<uint8_t> sp800Derive(const std::vector<uint8_t>& key, const std::string& label,
                                 const std::string& context) {
    std::vector<uint8_t> fixed;
    auto be32 = [&](uint32_t v) {
        for (int s = 24; s >= 0; s -= 8) fixed.push_back((v >> s) & 0xff);
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

class KeyMint {
  public:
    bool connect() {
        ABinderProcess_setThreadPoolMaxThreadCount(1);
        ABinderProcess_startThreadPool();
        ::ndk::SpAIBinder b(AServiceManager_getService(
                "android.hardware.security.keymint.IKeyMintDevice/default"));
        km_ = IKeyMintDevice::fromBinder(b);
        if (km_ == nullptr) return false;
        int32_t v = 0;
        km_->getInterfaceVersion(&v);
        LINE("KeyMint interface V%d", v);
        return true;
    }

    // Never calls upgradeKey or deleteKey: a key that needs an upgrade means the recovery
    // reports other OS/patch levels than the firmware, and an upgrade there is what
    // leaves the firmware with a key it can no longer use.
    Exit gcmDecrypt(const std::vector<uint8_t>& keyblob, const std::vector<uint8_t>& appId,
                    const std::vector<uint8_t>& nonceCtTag,
                    const std::optional<HardwareAuthToken>& authToken, std::vector<uint8_t>* out) {
        if (nonceCtTag.size() <= kGcmNonceLen + kGcmTagLen) return FAIL;
        std::vector<uint8_t> nonce(nonceCtTag.begin(), nonceCtTag.begin() + kGcmNonceLen);
        std::vector<uint8_t> body(nonceCtTag.begin() + kGcmNonceLen, nonceCtTag.end());

        std::vector<KeyParameter> params = {
                {Tag::BLOCK_MODE, KeyParameterValue::make<KeyParameterValue::blockMode>(BlockMode::GCM)},
                {Tag::PADDING,
                 KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::NONE)},
                {Tag::MAC_LENGTH, KeyParameterValue::make<KeyParameterValue::integer>(128)},
                {Tag::NONCE, KeyParameterValue::make<KeyParameterValue::blob>(nonce)},
        };
        if (!appId.empty())
            params.push_back(
                    {Tag::APPLICATION_ID, KeyParameterValue::make<KeyParameterValue::blob>(appId)});

        BeginResult begun;
        auto st = km_->begin(KeyPurpose::DECRYPT, keyblob, params, authToken, &begun);
        if (st.getServiceSpecificError() == static_cast<int32_t>(ErrorCode::KEY_REQUIRES_UPGRADE)) {
            LINE("  KeyMint says the key needs an upgrade: the recovery's OS version or patch "
                 "level differs from the firmware's. Refusing, nothing was changed.");
            return NEEDS_UPGRADE;
        }
        if (!st.isOk() || begun.operation == nullptr) {
            logStatus("begin(DECRYPT)", st);
            return FAIL;
        }
        std::vector<uint8_t> partial, tail;
        st = begun.operation->update(body, authToken, std::nullopt, &partial);
        if (!st.isOk()) {
            logStatus("update", st);
            begun.operation->abort();
            return FAIL;
        }
        st = begun.operation->finish(std::nullopt, std::nullopt, authToken, std::nullopt,
                                     std::nullopt, &tail);
        if (!st.isOk()) {
            logStatus("finish", st);
            return FAIL;
        }
        out->assign(partial.begin(), partial.end());
        out->insert(out->end(), tail.begin(), tail.end());
        return OK;
    }

  private:
    static void logStatus(const char* what, const ::ndk::ScopedAStatus& st) {
        LINE("  %s: ex=%d serviceSpecific=%d msg=%s", what, st.getExceptionCode(),
             st.getServiceSpecificError(), st.getMessage() ? st.getMessage() : "(none)");
    }

    std::shared_ptr<IKeyMintDevice> km_;
};

// vold KeyStorage retrieveKey, read-only. An empty secret means the key is wrapped by a
// KeyMint key; otherwise it is wrapped by a key derived from the secret alone.
Exit retrieveKey(KeyMint& km, const std::string& dir, const std::vector<uint8_t>& secret,
                 std::vector<uint8_t>* key) {
    std::vector<uint8_t> version, secdis, encrypted, blob;
    if (!readFile(dir + "/version", &version) || version != std::vector<uint8_t>{'1'}) {
        LINE("  %s/version missing or not 1", dir.c_str());
        return FAIL;
    }
    if (!readFile(dir + "/encrypted_key", &encrypted)) {
        LINE("  %s/encrypted_key missing", dir.c_str());
        return FAIL;
    }
    std::vector<uint8_t> appId;
    if (exists(dir + "/secdiscardable")) {
        if (!readFile(dir + "/secdiscardable", &secdis)) return FAIL;
        appId = personalizedHash("Android secdiscardable SHA512", secdis);
    }
    appId.insert(appId.end(), secret.begin(), secret.end());

    if (!secret.empty()) {
        std::vector<uint8_t> kek = personalizedHash("Android key wrapping key generation SHA512", appId);
        kek.resize(32);
        if (!swGcmDecrypt(kek, encrypted, key)) {
            LINE("  %s: decrypt with the secret failed", dir.c_str());
            return FAIL;
        }
        return OK;
    }
    if (!readFile(dir + "/keymaster_key_blob", &blob)) {
        LINE("  %s/keymaster_key_blob missing", dir.c_str());
        return FAIL;
    }
    return km.gcmDecrypt(blob, appId, encrypted, std::nullopt, key);
}

bool addFscryptKey(const std::vector<uint8_t>& raw, const char* what) {
    int dfd = open(DATA_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        LINE("  open(" DATA_ROOT "): %s", strerror(errno));
        return false;
    }
    std::vector<uint8_t> buf(sizeof(fscrypt_add_key_arg_local) + raw.size(), 0);
    auto* arg = reinterpret_cast<fscrypt_add_key_arg_local*>(buf.data());
    arg->key_spec.type = KEY_SPEC_TYPE_IDENTIFIER;
    arg->raw_size = static_cast<__u32>(raw.size());
    memcpy(arg->raw, raw.data(), raw.size());
    int rc = ioctl(dfd, FS_IOC_ADD_ENCRYPTION_KEY_LOCAL, arg);
    close(dfd);
    if (rc != 0) {
        LINE("  FS_IOC_ADD_ENCRYPTION_KEY (%s): %s", what, strerror(errno));
        return false;
    }
    LINE("  %s key installed, id %s", what, hex(arg->key_spec.u.identifier, 16).c_str());
    return true;
}

void dmInit(dm_ioctl* io, size_t size, const char* name) {
    memset(io, 0, size);
    io->version[0] = DM_VERSION_MAJOR;
    io->version[1] = DM_VERSION_MINOR;
    io->version[2] = DM_VERSION_PATCHLEVEL;
    io->data_size = size;
    io->data_start = sizeof(dm_ioctl);
    strncpy(io->name, name, sizeof(io->name) - 1);
}

// Same table vold's MetadataCrypt builds with options_format v2 (dm-default-key, set_dun).
bool createDefaultKeyDevice(const std::vector<uint8_t>& key, const std::string& blkdev,
                            std::string* dmPath) {
    int bfd = open(blkdev.c_str(), O_RDONLY | O_CLOEXEC);
    if (bfd < 0) {
        LINE("  open(%s): %s", blkdev.c_str(), strerror(errno));
        return false;
    }
    uint64_t bytes = 0;
    int rc = ioctl(bfd, BLKGETSIZE64, &bytes);
    close(bfd);
    if (rc != 0) return false;
    uint64_t nrSec = (bytes / 512) & ~7ull;

    std::string params = "aes-xts-plain64 " + hex(key.data(), key.size()) + " 0 " + blkdev +
                         " 0 3 allow_discards sector_size:4096 iv_large_sectors";

    int ctl = open("/dev/device-mapper", O_RDWR | O_CLOEXEC);
    if (ctl < 0) {
        LINE("  open(/dev/device-mapper): %s", strerror(errno));
        return false;
    }
    std::vector<uint8_t> buf(sizeof(dm_ioctl) + sizeof(dm_target_spec) + params.size() + 8, 0);
    auto* io = reinterpret_cast<dm_ioctl*>(buf.data());

    dmInit(io, buf.size(), kDmName);
    if (ioctl(ctl, DM_DEV_CREATE, io) != 0) {
        LINE("  DM_DEV_CREATE: %s", strerror(errno));
        close(ctl);
        return false;
    }
    dev_t dev = io->dev;

    dmInit(io, buf.size(), kDmName);
    io->target_count = 1;
    auto* spec = reinterpret_cast<dm_target_spec*>(buf.data() + sizeof(dm_ioctl));
    spec->sector_start = 0;
    spec->length = nrSec;
    strncpy(spec->target_type, "default-key", sizeof(spec->target_type) - 1);
    memcpy(buf.data() + sizeof(dm_ioctl) + sizeof(dm_target_spec), params.c_str(), params.size());
    spec->next = sizeof(dm_target_spec) + ((params.size() + 1 + 7) & ~7ul);
    bool ok = ioctl(ctl, DM_TABLE_LOAD, io) == 0;
    if (!ok) LINE("  DM_TABLE_LOAD: %s", strerror(errno));

    if (ok) {
        dmInit(io, buf.size(), kDmName);
        ok = ioctl(ctl, DM_DEV_SUSPEND, io) == 0;  // no DM_SUSPEND_FLAG: resume
        if (!ok) LINE("  DM_DEV_SUSPEND (resume): %s", strerror(errno));
    }
    if (!ok) {
        dmInit(io, buf.size(), kDmName);
        ioctl(ctl, DM_DEV_REMOVE, io);
        close(ctl);
        return false;
    }
    close(ctl);
    std::fill(params.begin(), params.end(), '\0');

    *dmPath = "/dev/block/dm-" + std::to_string(minor(dev));
    for (int i = 0; i < 50 && !exists(*dmPath); i++) usleep(100000);
    if (!exists(*dmPath) && mknod(dmPath->c_str(), S_IFBLK | 0600, dev) != 0) {
        LINE("  mknod(%s): %s", dmPath->c_str(), strerror(errno));
        return false;
    }
    mkdir("/dev/block/mapper", 0755);
    unlink("/dev/block/mapper/userdata");
    symlink(dmPath->c_str(), "/dev/block/mapper/userdata");
    return true;
}

int cmdMetadata(KeyMint& km, const std::string& blkdev) {
    LINE("===== metadata =====");
    if (exists("/dev/block/mapper/userdata")) {
        LINE("/dev/block/mapper/userdata already exists");
        return OK;
    }
    std::vector<uint8_t> key;
    Exit e = retrieveKey(km, kMetadataKeyDir, {}, &key);
    if (e != OK) return e;
    if (key.size() != 64) {
        LINE("metadata key is %zuB, expected 64", key.size());
        return FAIL;
    }
    std::string dmPath;
    bool ok = createDefaultKeyDevice(key, blkdev, &dmPath);
    std::fill(key.begin(), key.end(), 0);
    if (!ok) return FAIL;
    LINE("dm-default-key %s -> %s", blkdev.c_str(), dmPath.c_str());
    return OK;
}

int cmdDe(KeyMint& km) {
    LINE("===== de =====");
    struct {
        const char* dir;
        const char* what;
    } keys[] = {{kSystemDeKeyDir, "system DE"}, {kUser0DeKeyDir, "user 0 DE"}};
    for (auto& k : keys) {
        std::vector<uint8_t> key;
        Exit e = retrieveKey(km, k.dir, {}, &key);
        if (e != OK) return e;
        bool ok = addFscryptKey(key, k.what);
        std::fill(key.begin(), key.end(), 0);
        if (!ok) return FAIL;
    }
    return OK;
}

// sp-handle is a signed int64 decimal; the spblob filenames use its unsigned hex form.
bool getProtectorHandle(std::string* handleHex) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2("file:" DATA_ROOT "/system/locksettings.db?mode=ro&immutable=1", &db,
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
            char b[24];
            snprintf(b, sizeof(b), "%016llx",
                     static_cast<unsigned long long>(strtoll(v, nullptr, 10)));
            *handleHex = b;
            ok = true;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok;
}

bool getProtectorKeyBlob(const std::string& handleHex, std::vector<uint8_t>* blob) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2("file:" DATA_ROOT "/misc/keystore/persistent.sqlite?mode=ro&immutable=1", &db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    const char* sql =
            "SELECT b.blob FROM blobentry b JOIN keyentry k ON b.keyentryid=k.id "
            "WHERE k.alias=? AND b.subcomponent_type=0";
    // the alias is formatted with %x, so a leading zero nibble is not padded
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

enum { CRED_NONE = -1, CRED_PATTERN = 1, CRED_PIN = 3, CRED_PASSWORD = 4 };

// PasswordData, big-endian: int credentialType; byte logN; byte logR; byte logP;
// int saltLength; byte[] salt; int gatekeeperHandleLength; byte[] gatekeeperHandle.
bool readPasswordData(const std::string& handleHex, int32_t* credType, int* logN, int* logR,
                      int* logP, std::vector<uint8_t>* salt, std::vector<uint8_t>* gkHandle) {
    std::vector<uint8_t> d;
    if (!readFile(std::string(kSpblobDir) + handleHex + ".pwd", &d) || d.size() < 11) return false;
    auto be32 = [&](size_t o) -> int32_t {
        return static_cast<int32_t>((uint32_t)d[o] << 24 | (uint32_t)d[o + 1] << 16 |
                                    (uint32_t)d[o + 2] << 8 | (uint32_t)d[o + 3]);
    };
    *credType = be32(0);
    *logN = d[4];
    *logR = d[5];
    *logP = d[6];
    int32_t saltLen = be32(7);
    if (saltLen < 0 || static_cast<size_t>(11 + saltLen) > d.size()) return false;
    salt->assign(d.begin() + 11, d.begin() + 11 + saltLen);
    size_t o = 11 + saltLen;
    if (o + 4 <= d.size()) {
        int32_t hLen = be32(o);
        if (hLen > 0 && o + 4 + hLen <= d.size())
            gkHandle->assign(d.begin() + o + 4, d.begin() + o + 4 + hLen);
    }
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
// verify runs in a helper outside the firmware linker.
bool gatekeeperVerify(const std::vector<uint8_t>& gkHandle,
                      const std::vector<uint8_t>& stretchedLskf, HardwareAuthToken* out) {
    std::vector<uint8_t> gkInput = personalizedHash("user-gk-authentication", stretchedLskf);
    std::string cmd = "/system/bin/gk_verify 100000 " + hex(gkHandle.data(), gkHandle.size()) +
                      " " + hex(gkInput.data(), gkInput.size());
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_PRELOAD");
    FILE* f = popen(cmd.c_str(), "r");
    if (f == nullptr) return false;
    char buf[256] = {0};
    if (fgets(buf, sizeof(buf), f) == nullptr) buf[0] = 0;
    int rc = pclose(f);
    std::string tokenHex(buf);
    while (!tokenHex.empty() && (tokenHex.back() == '\n' || tokenHex.back() == '\r'))
        tokenHex.pop_back();
    std::vector<uint8_t> token;
    if (rc != 0 || !unhex(tokenHex, &token) || !parseAuthToken(token, out)) {
        LINE("  gatekeeper rejected the credential (gk_verify exit %d)", rc);
        return false;
    }
    return true;
}

// LockSettingsService: protectorSecret = stretchedLskf || personalizedHash(secdiscardable),
// sp = GCM(GCM(spblob, KeyMint key synthetic_password_<handle>), application-id hash).
int cmdCe(KeyMint& km, const std::string& credential) {
    LINE("===== ce =====");
    std::string handle;
    if (!getProtectorHandle(&handle)) {
        LINE("no sp-handle for user 0 in locksettings.db");
        return FAIL;
    }
    LINE("protector %s", handle.c_str());

    int32_t credType = CRED_NONE;
    int lN = 0, lR = 0, lP = 0;
    std::vector<uint8_t> salt, gkHandle, stretched;
    if (!readPasswordData(handle, &credType, &lN, &lR, &lP, &salt, &gkHandle) ||
        credType == CRED_NONE) {
        stretched.assign(32, 0);
        memcpy(stretched.data(), "default-password", 16);
        LINE("credential: none");
    } else if (credential.empty()) {
        // the recovery picks its input page from this: 2 pattern, 3 pin, anything else a keyboard
        int pwtype = credType == CRED_PATTERN ? 2 : (credType == CRED_PIN ? 3 : 0);
        FILE* f = fopen("/tmp/.ce_pwtype", "w");
        if (f) {
            fprintf(f, "%d", pwtype);
            fclose(f);
        }
        LINE("credential of type %d needed", credType);
        return NEED_CREDENTIAL;
    } else {
        stretched.assign(32, 0);
        if (EVP_PBE_scrypt(credential.data(), credential.size(), salt.data(), salt.size(),
                           1ull << lN, 1ull << lR, 1ull << lP, 64ull * 1024 * 1024,
                           stretched.data(), 32) != 1) {
            LINE("scrypt failed");
            return FAIL;
        }
    }

    // with a credential the protector key is bound to the secure user id, so KeyMint
    // wants a fresh gatekeeper token
    std::optional<HardwareAuthToken> authToken;
    if (credType != CRED_NONE) {
        HardwareAuthToken hat;
        if (gkHandle.empty() || !gatekeeperVerify(gkHandle, stretched, &hat)) return BAD_CREDENTIAL;
        authToken = hat;
    }

    std::vector<uint8_t> keyBlob, spblob, secdis;
    if (!getProtectorKeyBlob(handle, &keyBlob)) {
        LINE("synthetic_password_%s not in persistent.sqlite", handle.c_str());
        return FAIL;
    }
    if (!readFile(std::string(kSpblobDir) + handle + ".spblob", &spblob) || spblob.size() < 3 ||
        !readFile(std::string(kSpblobDir) + handle + ".secdis", &secdis)) {
        LINE("protector files for %s missing", handle.c_str());
        return FAIL;
    }
    LINE("spblob v%d type %d", spblob[0], spblob[1]);

    std::vector<uint8_t> protectorSecret = stretched;
    std::vector<uint8_t> sdh = personalizedHash("secdiscardable-transform", secdis);
    protectorSecret.insert(protectorSecret.end(), sdh.begin(), sdh.end());

    std::vector<uint8_t> intermediate, sp;
    Exit e = km.gcmDecrypt(keyBlob, {}, std::vector<uint8_t>(spblob.begin() + 2, spblob.end()),
                           authToken, &intermediate);
    if (e != OK) return e;
    std::vector<uint8_t> innerKey = personalizedHash("application-id", protectorSecret);
    innerKey.resize(32);
    if (!swGcmDecrypt(innerKey, intermediate, &sp)) {
        LINE("inner protector layer failed");
        return BAD_CREDENTIAL;
    }

    std::vector<uint8_t> secret =
            sp800Derive(sp, "fbe-key", "android-synthetic-password-personalization-context");
    std::vector<uint8_t> ceKey;
    e = retrieveKey(km, kUser0CeKeyDir, secret, &ceKey);
    std::fill(secret.begin(), secret.end(), 0);
    if (e != OK) return e;
    bool ok = addFscryptKey(ceKey, "user 0 CE");
    std::fill(ceKey.begin(), ceKey.end(), 0);
    return ok ? OK : FAIL;
}

}  // namespace

int main(int argc, char** argv) {
    std::string cmd = argc > 1 ? argv[1] : "";
    if (cmd != "metadata" && cmd != "de" && cmd != "ce") {
        fprintf(stderr, "usage: %s metadata <userdata blkdev> | de | ce [credential]\n", argv[0]);
        return FAIL;
    }
    if (cmd == "metadata" && argc < 3) return FAIL;

    KeyMint km;
    if (!km.connect()) {
        LINE("IKeyMintDevice/default not found");
        return FAIL;
    }
    if (cmd == "metadata") return cmdMetadata(km, argv[2]);
    if (cmd == "de") return cmdDe(km);
    return cmdCe(km, argc > 2 ? argv[2] : "");
}

#define LOG_TAG "apexservice_stub"

#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/binder_parcel.h>
#include <android/binder_process.h>
#include <android/binder_status.h>
#include <android/log.h>

namespace {

void* OnCreate(void* /*args*/) { return nullptr; }
void OnDestroy(void* /*userData*/) {}

// keystore2 only needs an empty active package list, so answer every method with
// a no-exception Status followed by a zero length vector
binder_status_t OnTransact(AIBinder* /*binder*/, transaction_code_t /*code*/,
                           const AParcel* /*in*/, AParcel* out) {
    if (out != nullptr) {
        AParcel_writeInt32(out, 0);
        AParcel_writeInt32(out, 0);
    }
    return STATUS_OK;
}

}  // namespace

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(2);
    ABinderProcess_startThreadPool();

    AIBinder_Class* clazz = AIBinder_Class_define(
        "android.apex.IApexService", OnCreate, OnDestroy, OnTransact);
    if (clazz == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "AIBinder_Class_define failed");
        return 1;
    }

    AIBinder* binder = AIBinder_new(clazz, nullptr);
    if (binder == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "AIBinder_new failed");
        return 1;
    }

    binder_status_t st = AServiceManager_addService(binder, "apexservice");
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "addService(apexservice) -> %d", st);
    if (st != STATUS_OK) {
        AIBinder_decStrong(binder);
        return 1;
    }

    ABinderProcess_joinThreadPool();
    AIBinder_decStrong(binder);
    return 0;
}

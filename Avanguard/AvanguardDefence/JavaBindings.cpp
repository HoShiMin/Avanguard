#include <jni.h>

static struct {
    JavaVM* vm;
    JNIEnv* env;
    bool IsBinded;
} JniInfo;

jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    jint status = vm->GetEnv(reinterpret_cast<void**>(&JniInfo.env), JNI_VERSION_1_8);
    if (status != JNI_OK) {
        if (status == JNI_EDETACHED) {
            status = vm->AttachCurrentThread(reinterpret_cast<void**>(&JniInfo.env), NULL);
        }
        else {
            return JNI_ERR;
        }
    }

    if (status != JNI_OK)
        return status;

    return JNI_VERSION_1_8;
}
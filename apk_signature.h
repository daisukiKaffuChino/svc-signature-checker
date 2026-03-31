#ifndef APK_SIGNATURE_H
#define APK_SIGNATURE_H

#include <jni.h>
#include <stdint.h>

#define SYS_OPENAT 56
#define SYS_READ   63
#define SYS_LSEEK  62
#define SYS_CLOSE  57

#define APK_SIG_XOR_KEY 0x66
#define APK_EXPECTED_SIGNATURE_HASH "YOUR_HASH"

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jstring JNICALL
Java_your_package_getSignatureString(JNIEnv *env, jclass thiz);

JNIEXPORT jboolean JNICALL
Java_your_package_checkNative(JNIEnv *env, jclass thiz);

#ifdef __cplusplus
}
#endif

#endif // APK_SIGNATURE_H
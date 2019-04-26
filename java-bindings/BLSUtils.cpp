//
// Created by Florian Cäsar on 2019-04-26.
//

#include "BLSUtils.h"

jint jniThrow(JNIEnv *env, const char *message, const char *cls)
{
    jclass exClass;
    exClass = env->FindClass(cls);
    if (exClass == nullptr) {
        return jniThrow(env, "Error while reporting error", "java/lang/Error");
    }

    return env->ThrowNew(exClass, message);
}

jint jniThrowBLS(JNIEnv *env, const char *message) {
    return jniThrow(env, message, "org/chia/jbls/BLSException");
}
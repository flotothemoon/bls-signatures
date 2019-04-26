//
// Created by Florian Cäsar on 2019-04-26.
//

#ifndef BLS_BLSUTILS_H
#define BLS_BLSUTILS_H


#include <jni.h>

jint jniThrow(JNIEnv *env, const char *message, const char *cls);
jint jniThrowBLS(JNIEnv *env, const char *message);


#endif //BLS_BLSUTILS_H

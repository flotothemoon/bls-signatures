//
// Created by Florian Cäsar on 2019-04-25.
//

#include <jni.h>
#include "../src/privatekey.hpp"
#include "../src/bls.hpp"
#include "org_chia_jbls_BLSPrivateKey.h"

using namespace bls;

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSPrivateKey__1constructFromSeed
        (JNIEnv *env, jclass cls, jbyteArray seed) {
    jsize length = (*env).GetArrayLength(seed);
    PrivateKey *pKey = new PrivateKey(PrivateKey::FromSeed((uint8_t *) seed, (size_t) length));
    return (jlong) pKey;
}

JNIEXPORT void JNICALL Java_org_chia_jbls_BLSPrivateKey__1delete
        (JNIEnv *env, jclass cls, jlong ptr) {
    auto *pKey = (PrivateKey *) ptr;
    delete(pKey);
}

JNIEXPORT jint JNICALL Java_org_chia_jbls_BLSPrivateKey__1getPrivateKeySize
        (JNIEnv *env, jclass cls) {
    return (jint) PrivateKey::PRIVATE_KEY_SIZE;
}
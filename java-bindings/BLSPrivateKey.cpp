//
// Created by Florian Cäsar on 2019-04-25.
//

#include <jni.h>
#include "../src/privatekey.hpp"
#include "../src/bls.hpp"
#include "org_chia_jbls_BLSPrivateKey.h"
#include <stdio.h>

using namespace bls;

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSPrivateKey__1aggregateInsecure
        (JNIEnv *env, jclass, jlongArray pkPtrs) {
    jlong *pkPtrsArray = env->GetLongArrayElements(pkPtrs, nullptr);
    jsize length = env->GetArrayLength(pkPtrs);
    std::vector<PrivateKey> pkVector;
    for (int i = 0; i < length; ++i) {
        auto pKey = (PrivateKey*) pkPtrsArray[i];
        pkVector.push_back(*pKey);
    }
    env->ReleaseLongArrayElements(pkPtrs, pkPtrsArray, 0);

    const PrivateKey &pkInsecureAggregate = PrivateKey::AggregateInsecure(pkVector);
    PrivateKey *pkInsecureAggregateCopy = new PrivateKey(pkInsecureAggregate);
    return (jlong) pkInsecureAggregateCopy;
}

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSPrivateKey__1constructFromSeed
        (JNIEnv *env, jclass, jbyteArray seed) {
    jsize length = env->GetArrayLength(seed);
    jbyte *seedArray = env->GetByteArrayElements(seed, nullptr);

    const PrivateKey &fromSeed = PrivateKey::FromSeed((uint8_t *) seedArray, (size_t) length);
    PrivateKey *pKeyCopy = new PrivateKey(fromSeed);

    env->ReleaseByteArrayElements(seed, seedArray, 0);

    return (jlong) pKeyCopy;
}

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSPrivateKey__1constructFromBytes
        (JNIEnv *env, jclass, jbyteArray bytes) {
    jbyte *seedArray = env->GetByteArrayElements(bytes, nullptr);

    const PrivateKey &fromBytes = PrivateKey::FromSeed((uint8_t *) seedArray, true);
    PrivateKey *pKeyCopy = new PrivateKey(fromBytes);

    env->ReleaseByteArrayElements(bytes, seedArray, 0);

    return (jlong) pKeyCopy;
}

JNIEXPORT void JNICALL Java_org_chia_jbls_BLSPrivateKey__1serialize
        (JNIEnv *env, jclass, jlong pkPtr, jbyteArray buffer) {
    uint8_t nativeBuffer[PrivateKey::PRIVATE_KEY_SIZE];
    PrivateKey pKey = *((PrivateKey*) pkPtr);
    pKey.Serialize(nativeBuffer);

    env->SetByteArrayRegion(buffer, 0, PrivateKey::PRIVATE_KEY_SIZE, (jbyte*) nativeBuffer);
}

JNIEXPORT void JNICALL Java_org_chia_jbls_BLSPrivateKey__1delete
        (JNIEnv *, jlong ptr) {
    auto *pKey = (PrivateKey *) ptr;
    delete(pKey);
}

JNIEXPORT jint JNICALL Java_org_chia_jbls_BLSPrivateKey__1getPrivateKeySize
        (JNIEnv *, jclass) {
    return (jint) PrivateKey::PRIVATE_KEY_SIZE;
}
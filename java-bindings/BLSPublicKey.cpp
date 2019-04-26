//
// Created by Florian Cäsar on 2019-04-25.
//

#include <jni.h>
#include "../src/publickey.hpp"
#include "../src/bls.hpp"
#include "org_chia_jbls_BLSPublicKey.h"
#include <stdio.h>

using namespace bls;

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSPublicKey__1aggregateInsecure
        (JNIEnv *env, jclass, jlongArray pkPtrs) {
    jlong *pkPtrsArray = env->GetLongArrayElements(pkPtrs, nullptr);
    jsize length = env->GetArrayLength(pkPtrs);
    std::vector<PublicKey> pkVector;
    for (int i = 0; i < length; ++i) {
        auto pKey = (PublicKey*) pkPtrsArray[i];
        pkVector.push_back(*pKey);
    }
    env->ReleaseLongArrayElements(pkPtrs, pkPtrsArray, 0);

    const PublicKey &pkInsecureAggregate = PublicKey::AggregateInsecure(pkVector);
    PublicKey *pkInsecureAggregateCopy = new PublicKey(pkInsecureAggregate);
    return (jlong) pkInsecureAggregateCopy;
}

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSPublicKey__1constructFromBytes
        (JNIEnv *env, jclass, jbyteArray bytes) {
    jbyte *bytesArray = env->GetByteArrayElements(bytes, nullptr);

    const PublicKey &pKeyFromBytes = PublicKey::FromBytes((uint8_t *) bytesArray);
    PublicKey *pKeyCopy = new PublicKey(pKeyFromBytes);

    env->ReleaseByteArrayElements(bytes, bytesArray, 0);

    return (jlong) pKeyCopy;
}

JNIEXPORT void JNICALL Java_org_chia_jbls_BLSPublicKey__1serialize
        (JNIEnv *env, jclass, jlong pkPtr, jbyteArray buffer) {
    uint8_t nativeBuffer[PublicKey::PUBLIC_KEY_SIZE];
    PublicKey pKey = *((PublicKey*) pkPtr);
    pKey.Serialize(nativeBuffer);

    env->SetByteArrayRegion(buffer, 0, PublicKey::PUBLIC_KEY_SIZE, (jbyte*) nativeBuffer);
}


JNIEXPORT void JNICALL Java_org_chia_jbls_BLSPublicKey__1delete
        (JNIEnv *, jlong ptr) {
    auto *pKey = (PublicKey *) ptr;
    delete(pKey);
}

JNIEXPORT jint JNICALL Java_org_chia_jbls_BLSPublicKey__1getPublicKeySize
        (JNIEnv *, jclass) {
    return (jint) PublicKey::PUBLIC_KEY_SIZE;
}


JNIEXPORT jint JNICALL Java_org_chia_jbls_BLSPublicKey__1getMessageHashSize
        (JNIEnv *, jclass) {
    return (jint) BLS::MESSAGE_HASH_LEN;
}
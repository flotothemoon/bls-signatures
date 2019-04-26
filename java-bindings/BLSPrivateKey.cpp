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

    const PrivateKey &pKeyFromSeed = PrivateKey::FromSeed((uint8_t *) seedArray, (size_t) length);
    PrivateKey *pKeyCopy = new PrivateKey(pKeyFromSeed);

    env->ReleaseByteArrayElements(seed, seedArray, 0);

    return (jlong) pKeyCopy;
}

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSPrivateKey__1constructFromBytes
        (JNIEnv *env, jclass, jbyteArray bytes) {
    jbyte *seedArray = env->GetByteArrayElements(bytes, nullptr);

    const PrivateKey &pKeyFromBytes = PrivateKey::FromBytes((uint8_t *) seedArray, true);
    PrivateKey *pKeyCopy = new PrivateKey(pKeyFromBytes);

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

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSPrivateKey__1signPrehashed
        (JNIEnv *env, jclass, jlong pkPtr, jbyteArray msgHash) {
    jbyte *msgHashArray = env->GetByteArrayElements(msgHash, nullptr);
    PrivateKey pKey = *((PrivateKey*) pkPtr);
    const Signature &sig = pKey.SignPrehashed((uint8_t *) msgHashArray);
    Signature* sigCopy = new Signature(sig);

    env->ReleaseByteArrayElements(msgHash, msgHashArray, 0);

    return (jlong) sigCopy;
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

JNIEXPORT jint JNICALL Java_org_chia_jbls_BLSPrivateKey__1getMessageHashSize
        (JNIEnv *, jclass) {
    return (jint) BLS::MESSAGE_HASH_LEN;
}
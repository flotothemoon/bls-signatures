//
// Created by Florian Cäsar on 2019-04-25.
//

#include <jni.h>
#include "../src/signature.hpp"
#include "../src/bls.hpp"
#include "org_chia_jbls_BLSSignature.h"
#include "BLSUtils.h"
#include <stdio.h>

using namespace bls;

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSSignature__1aggregate
        (JNIEnv *env, jclass, jlongArray sigPtrs) {
    jlong *sigPtrsArray = env->GetLongArrayElements(sigPtrs, nullptr);
    jsize length = env->GetArrayLength(sigPtrs);
    std::vector<Signature> sigVector;
    for (int i = 0; i < length; ++i) {
        auto pKey = (Signature*) sigPtrsArray[i];
        sigVector.push_back(*pKey);
    }
    env->ReleaseLongArrayElements(sigPtrs, sigPtrsArray, 0);

    const Signature &signatureAggregate = Signature::AggregateSigs(sigVector);
    Signature *signatureAggregateCpy = new Signature(signatureAggregate);
    return (jlong) signatureAggregateCpy;
}

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSSignature__1constructFromBytes
        (JNIEnv *env, jclass, jbyteArray bytes) {
    jbyte *bytesArray = env->GetByteArrayElements(bytes, nullptr);

    try {
        const Signature &sigFromBytes = Signature::FromBytes((uint8_t *) bytesArray);
        auto *sigCopy = new Signature(sigFromBytes);
        env->ReleaseByteArrayElements(bytes, bytesArray, 0);

        return (jlong) sigCopy;
    } catch (...) {
        env->ReleaseByteArrayElements(bytes, bytesArray, 0);
        jniThrowBLS(env, "Error while deserializing signature");

        return 0L;
    }
}

JNIEXPORT void JNICALL Java_org_chia_jbls_BLSSignature__1serialize
        (JNIEnv *env, jclass, jlong pkPtr, jbyteArray buffer) {
    uint8_t nativeBuffer[Signature::SIGNATURE_SIZE];
    Signature sig = *((Signature*) pkPtr);
    sig.Serialize(nativeBuffer);

    env->SetByteArrayRegion(buffer, 0, Signature::SIGNATURE_SIZE, (jbyte*) nativeBuffer);
}

JNIEXPORT jboolean JNICALL Java_org_chia_jbls_BLSSignature__1verify
        (JNIEnv *env, jclass, jlong ptr, jlongArray pubKeyPtrs, jobjectArray msgHashes) {
    jlong *pubKeyPtrsArray = env->GetLongArrayElements(pubKeyPtrs, nullptr);
    jsize length = env->GetArrayLength(pubKeyPtrs);
    std::vector<AggregationInfo> aggregationInfos;
    for (int i = 0; i < length; ++i) {
        auto pKey = *((PublicKey*) pubKeyPtrsArray[i]);
        jbyteArray msgHash = (jbyteArray) env->GetObjectArrayElement(msgHashes, i);
        jbyte *msgHashArray = env->GetByteArrayElements(msgHash, nullptr);

        aggregationInfos.push_back(AggregationInfo::FromMsgHash(pKey, (uint8_t*) msgHashArray));

        env->ReleaseByteArrayElements(msgHash, msgHashArray, 0);
    }
    env->ReleaseLongArrayElements(pubKeyPtrs, pubKeyPtrsArray, 0);

    AggregationInfo mergedAggregationInfo = AggregationInfo::MergeInfos(aggregationInfos);
    Signature signature = *((Signature *) ptr);
    signature.SetAggregationInfo(mergedAggregationInfo);
    return (jboolean) signature.Verify();
}

JNIEXPORT void JNICALL Java_org_chia_jbls_BLSSignature__1delete
        (JNIEnv *, jclass, jlong ptr) {
    auto *sig = (Signature *) ptr;
    delete(sig);
}

JNIEXPORT jint JNICALL Java_org_chia_jbls_BLSSignature__1getSignatureSize
        (JNIEnv *, jclass) {
    return (jint) Signature::SIGNATURE_SIZE;
}
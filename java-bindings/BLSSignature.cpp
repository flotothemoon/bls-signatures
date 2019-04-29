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
        (JNIEnv *env, jclass, jlongArray sigPtrs, jobjectArray aggrPubKeys, jobjectArray aggrMsgHashes) {
    std::vector<Signature> sigVector;
    std::vector<std::vector<PublicKey>> aggrPubKeysVector;
    std::vector<std::vector<uint8_t *>> aggrMsgHashesVector;
    try {
        jlong *sigPtrsArray = env->GetLongArrayElements(sigPtrs, nullptr);
        jsize length = env->GetArrayLength(sigPtrs);
        for (int i = 0; i < length; ++i) {
            auto sig = *(Signature*) sigPtrsArray[i];

            std::vector<uint8_t *> msgHashesVector;
            std::vector<PublicKey> pubKeysVector;
            auto pubKeysArray = (jlongArray) env->GetObjectArrayElement(aggrPubKeys, i);
            jlong* pubKeys = env->GetLongArrayElements(pubKeysArray, nullptr);
            auto msgHashesArray = (jobjectArray) env->GetObjectArrayElement(aggrMsgHashes, i);
            jsize numMsgHashes = env->GetArrayLength(msgHashesArray);
            for (int j = 0; j < numMsgHashes; ++j) {
                auto msgHashArray = (jbyteArray) (env->GetObjectArrayElement(msgHashesArray, j));
                jbyte *msgHashes = env->GetByteArrayElements(msgHashArray, nullptr);
                msgHashesVector.push_back((uint8_t *) msgHashes);
                env->ReleaseByteArrayElements(msgHashArray, msgHashes, 0);

                auto pKey = *((PublicKey*) pubKeys[i]);
                pubKeysVector.push_back(pKey);
            }

            env->ReleaseLongArrayElements(pubKeysArray, pubKeys, 0);

            aggrPubKeysVector.push_back(pubKeysVector);
            aggrMsgHashesVector.push_back(msgHashesVector);
            sigVector.push_back(sig);
        }
        env->ReleaseLongArrayElements(sigPtrs, sigPtrsArray, 0);
    } catch (...) {
        jniThrowBLS(env, "Error while creating signature array");
        return (jlong) 0;
    }

    try {
        const Signature &signatureAggregate = Signature::AggregateSigsInternal(
                sigVector,
                aggrPubKeysVector,
                aggrMsgHashesVector
        );
        auto *signatureAggregateCpy = new Signature(signatureAggregate);
        return (jlong) signatureAggregateCpy;
    } catch (...) {
        jniThrowBLS(env, "Error while aggregating signatures");
        return (jlong) 0;
    }
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
    try {
        for (int i = 0; i < length; ++i) {
            auto pKey = *((PublicKey*) pubKeyPtrsArray[i]);
            auto msgHash = (jbyteArray) env->GetObjectArrayElement(msgHashes, i);
            jbyte *msgHashArray = env->GetByteArrayElements(msgHash, nullptr);

            aggregationInfos.push_back(AggregationInfo::FromMsgHash(pKey, (uint8_t*) msgHashArray));

            env->ReleaseByteArrayElements(msgHash, msgHashArray, 0);
        }
        env->ReleaseLongArrayElements(pubKeyPtrs, pubKeyPtrsArray, 0);
    } catch (...) {
        jniThrowBLS(env, "Error while creating aggregation info");
        return false;
    }

    try {
        AggregationInfo mergedAggregationInfo = AggregationInfo::MergeInfos(aggregationInfos);
        Signature signature = *((Signature *) ptr);
        signature.SetAggregationInfo(mergedAggregationInfo);
        return (jboolean) signature.Verify();
    } catch (...) {
        jniThrowBLS(env, "Error while verifying signature");
        return false;
    }
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
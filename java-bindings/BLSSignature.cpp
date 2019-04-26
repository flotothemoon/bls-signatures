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

JNIEXPORT jlong JNICALL Java_org_chia_jbls_BLSSignature__1constructFromBytes
        (JNIEnv *env, jclass, jbyteArray bytes) {
    jbyte *seedArray = env->GetByteArrayElements(bytes, nullptr);

    try {
        const Signature &sigFromBytes = Signature::FromBytes((uint8_t *) seedArray);
        auto *sigCopy = new Signature(sigFromBytes);
        env->ReleaseByteArrayElements(bytes, seedArray, 0);

        return (jlong) sigCopy;
    } catch (...) {
        env->ReleaseByteArrayElements(bytes, seedArray, 0);
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

JNIEXPORT void JNICALL Java_org_chia_jbls_BLSSignature__1delete
        (JNIEnv *, jclass, jlong ptr) {
    auto *sig = (Signature *) ptr;
    delete(sig);
}

JNIEXPORT jint JNICALL Java_org_chia_jbls_BLSSignature__1getSignatureSize
        (JNIEnv *, jclass) {
    return (jint) Signature::SIGNATURE_SIZE;
}
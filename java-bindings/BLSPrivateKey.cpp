//
// Created by Florian Cäsar on 2019-04-25.
//

#include <jni.h>
#include "../src/privatekey.hpp"
#include "../src/bls.hpp"
#include "org_chia_jbls_BLSPrivateKey.h"

using namespace bls;

JNIEXPORT jint JNICALL Java_org_chia_jbls_BLSPrivateKey__1getPrivateKeySize
        (JNIEnv *, jclass) {
    return (jint) PrivateKey::PRIVATE_KEY_SIZE;
}
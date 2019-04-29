CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 11)

find_package(Java REQUIRED)
find_package(JNI REQUIRED)
message (STATUS "Java_VERSION_STRING=${Java_VERSION_STRING}")
if (JNI_FOUND)
    message (STATUS "JNI_INCLUDE_DIRS=${JNI_INCLUDE_DIRS}")
    message (STATUS "JNI_LIBRARIES=${JNI_LIBRARIES}")
endif()

include(UseJava)

enable_testing()
project(JNIBLS)

# compile BLSPrivateKey.java to class file
set(CMAKE_JAVA_COMPILE_FLAGS "-source" "1.8" "-target" "1.8")
add_jar(JNIBLS org/chia/jbls/JNIBLS.java org/chia/jbls/BLSPrivateKey.java org/chia/jbls/BLSPublicKey.java org/chia/jbls/BLSSignature.java org/chia/jbls/BLSException.java)
get_target_property(_jarFile JNIBLS JAR_FILE)
get_target_property(_classDir JNIBLS CLASSDIR)

# generate JNIBLS.h stub
set (_stubDir "${CMAKE_CURRENT_BINARY_DIR}")
add_custom_command(
        OUTPUT BLSPrivateKey.h BLSPublicKey.h BLSSignature.h
        COMMAND ${Java_JAVAH_EXECUTABLE} -verbose
            -classpath ${_classDir}
            -d ${_stubDir}
            -jni org.chia.jbls.JNIBLS org.chia.jbls.BLSPrivateKey org.chia.jbls.BLSPublicKey org.chia.jbls.BLSSignature org.chia.jbls.BLSException
        DEPENDS JNIBLS
)

# generate libBLS.jnilib
add_library(jbls MODULE BLSPrivateKey.cpp BLSPrivateKey.h BLSPublicKey.h  BLSPublicKey.cpp BLSSignature.h BLSSignature.cpp BLSUtils.cpp BLSUtils.h)
if (SODIUM_FOUND)
    target_link_libraries(jbls PRIVATE ${JNI_LIBRARIES} blstmp relic_s sodium)
else ()
    target_link_libraries(jbls PRIVATE ${JNI_LIBRARIES} blstmp relic_s)
endif ()

# add test to run JNIBLS
add_test(NAME TestJNIBLS
        COMMAND ${Java_JAVA_EXECUTABLE}
        -Djava.library.path=${CMAKE_CURRENT_BINARY_DIR}
        -cp ${_jarFile} JNIBLS)

include_directories(
  ${JNI_INCLUDE_DIRS}
  ${_classDir}
  ${_stubDir}
  ${INCLUDE_DIRECTORIES}
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/relic/include
  ${CMAKE_BINARY_DIR}/contrib/relic/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
)


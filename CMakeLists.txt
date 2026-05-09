cmake_minimum_required(VERSION 3.10)

project(FIT4012_AES)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(encrypt encrypt.cpp)
add_executable(decrypt decrypt.cpp)
add_executable(cbc_encrypt cbc_encrypt.cpp)
add_executable(cbc_decrypt cbc_decrypt.cpp)

enable_testing()

add_test(NAME CompileTest
         COMMAND bash tests/test_aes_compile.sh)

add_test(NAME RoundTripTest
         COMMAND bash tests/test_encrypt_decrypt_roundtrip.sh)

add_test(NAME MultiBlockTest
         COMMAND bash tests/test_multiblock_padding.sh)

add_test(NAME TamperTest
         COMMAND bash tests/test_tamper_negative.sh)

add_test(NAME WrongKeyTest
         COMMAND bash tests/test_wrong_key_negative.sh)
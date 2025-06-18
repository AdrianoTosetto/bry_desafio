cmake_minimum_required(VERSION 3.5)
project (desafio_bry)

find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE INCLUDE_FILES "include/*.h")
file(GLOB_RECURSE HEADER_FILES "src/*.h")

add_executable(desafio_bry src/server.cc ${INCLUDE_FILES} ${HEADER_FILES})

target_link_libraries(desafio_bry PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(desafio_bry PRIVATE
    -std=c++17
    -lssl
    -lcrypto
    -pthread
)

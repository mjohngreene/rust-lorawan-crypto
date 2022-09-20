project(lorawan-crypto)
cmake_minimum_required(VERSION 3.10)

add_compile_definitions(
        AES_DEC_PREKEYED
)

add_library(lorawan-crypto STATIC
        aes.c
        cmac.c
        utilities.c
        )

install(TARGETS lorawan-crypto
        DESTINATION lib
        )
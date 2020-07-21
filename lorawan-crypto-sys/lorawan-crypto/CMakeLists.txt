cmake_minimum_required(VERSION 3.10)

add_compile_definitions(
        AES_DEC_PREKEYED HAVE_UINT_32T
)

add_library(lorawan-crypto STATIC
        aes.c
        cmac.c
        utilities.c
        )

install(TARGETS lorawan-crypto
        DESTINATION lib
        )
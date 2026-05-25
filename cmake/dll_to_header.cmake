# cmake/dll_to_header.cmake
# Appelé en mode script (-P) après la compilation de la DLL.
# Lit le fichier binaire DLL_PATH et génère HEADER_PATH contenant :
#   extern const unsigned char kEmbeddedDll[];
#   extern const unsigned int  kEmbeddedDllSize;

cmake_minimum_required(VERSION 3.15)

if(NOT DEFINED DLL_PATH OR NOT DEFINED HEADER_PATH)
    message(FATAL_ERROR "Usage: cmake -DDLL_PATH=<dll> -DHEADER_PATH=<h> -P dll_to_header.cmake")
endif()

if(NOT EXISTS "${DLL_PATH}")
    message(FATAL_ERROR "DLL introuvable : ${DLL_PATH}")
endif()

file(READ "${DLL_PATH}" RAW_BYTES HEX)
string(LENGTH "${RAW_BYTES}" HEX_LEN)
math(EXPR BYTE_COUNT "${HEX_LEN} / 2")

# Grouper par 2 caractères hex → "0xNN," avec sauts de ligne tous les 16 octets
set(ARRAY_BODY "")
set(COL 0)
math(EXPR LAST_IDX "${BYTE_COUNT} - 1")

foreach(IDX RANGE 0 ${LAST_IDX})
    math(EXPR HEX_IDX "${IDX} * 2")
    string(SUBSTRING "${RAW_BYTES}" ${HEX_IDX} 2 BYTE_HEX)

    if(IDX EQUAL LAST_IDX)
        string(APPEND ARRAY_BODY "0x${BYTE_HEX}")
    else()
        string(APPEND ARRAY_BODY "0x${BYTE_HEX},")
    endif()

    math(EXPR COL "${COL} + 1")
    if(COL EQUAL 16 AND NOT IDX EQUAL LAST_IDX)
        string(APPEND ARRAY_BODY "\n    ")
        set(COL 0)
    endif()
endforeach()

set(HEADER_CONTENT
"/* dll_data.h — généré automatiquement par CMake. Ne pas modifier. */
#pragma once
#ifdef __cplusplus
extern \"C\" {
#endif

static const unsigned char kEmbeddedDll[] = {
    ${ARRAY_BODY}
};
static const unsigned int kEmbeddedDllSize = ${BYTE_COUNT}U;

#ifdef __cplusplus
}
#endif
")

file(WRITE "${HEADER_PATH}" "${HEADER_CONTENT}")
message(STATUS "dll_data.h généré : ${BYTE_COUNT} octets -> ${HEADER_PATH}")

cmake_minimum_required(VERSION 3.15)
project(DPSCounter C CXX)

# ======================================================
# Configuration cible : x86 MSVC, Windows
# ======================================================
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "Ce projet doit être compilé en 32 bits (x86). "
        "Utilisez: cmake -A Win32 ...")
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ======================================================
# Chemin DirectX SDK
# Priorité : -DDXSDK_DIR  →  %DXSDK_DIR%  →  ../BuffGuild.exe/dxsdk  →  ../injectDLL/dxsdk/sdk
# ======================================================
if(NOT DEFINED DXSDK_DIR)
    if(DEFINED ENV{DXSDK_DIR})
        set(DXSDK_DIR "$ENV{DXSDK_DIR}")
    else()
        # Tentative de localisation relative (sibling du dossier courant)
        set(_GUESS1 "${CMAKE_CURRENT_SOURCE_DIR}/../BuffGuild.exe/dxsdk")
        set(_GUESS2 "${CMAKE_CURRENT_SOURCE_DIR}/../injectDLL/dxsdk/sdk")
        if(EXISTS "${_GUESS1}/Include/d3dx9.h")
            get_filename_component(DXSDK_DIR "${_GUESS1}" ABSOLUTE)
            message(STATUS "DXSDK localise automatiquement : ${DXSDK_DIR}")
        elseif(EXISTS "${_GUESS2}/Include/d3dx9.h")
            get_filename_component(DXSDK_DIR "${_GUESS2}" ABSOLUTE)
            message(STATUS "DXSDK localise automatiquement : ${DXSDK_DIR}")
        else()
            message(FATAL_ERROR
                "DXSDK_DIR n'est pas défini et aucun DXSDK trouvé automatiquement.\n"
                "Passez -DDXSDK_DIR=<chemin> à CMake ou définissez la variable "
                "d'environnement DXSDK_DIR.")
        endif()
    endif()
endif()

string(REPLACE "\\" "/" DXSDK_DIR "${DXSDK_DIR}")
message(STATUS "DirectX SDK : ${DXSDK_DIR}")

# ======================================================
# DLL — dpscounter_dll
# ======================================================
add_library(DPSCounter_DLL SHARED
    src/dpscounter_dll.cpp
)

target_include_directories(DPSCounter_DLL PRIVATE
    "${DXSDK_DIR}/Include"
)

target_link_directories(DPSCounter_DLL PRIVATE
    "${DXSDK_DIR}/Lib/x86"
)

target_link_libraries(DPSCounter_DLL PRIVATE
    d3d9.lib
    d3dx9.lib
    ws2_32.lib
    kernel32.lib
    user32.lib
)

target_compile_options(DPSCounter_DLL PRIVATE
    /W3          # niveau d'avertissement modéré
    /WX-         # ne pas traiter les avertissements comme erreurs
    /O2          # optimisation vitesse
    /MT          # CRT statique (pas de dépendance DLL runtime)
    /GS-         # désactiver buffer security check (hooks inline sensibles)
    /Oy-         # conserver les frame pointers (utile pour le débogage)
    /EHsc        # exceptions C++ standard
    /DWIN32
    /D_WINDOWS
    /DUNICODE
    /D_UNICODE
)

set_target_properties(DPSCounter_DLL PROPERTIES
    OUTPUT_NAME "dpscounter"
    PREFIX ""
    SUFFIX ".dll"
)

# ======================================================
# Conversion DLL → header C (dll_data.h)
# Dépend de la cible DPSCounter_DLL
# ======================================================
set(DLL_OUTPUT_PATH  "${CMAKE_CURRENT_BINARY_DIR}/dpscounter.dll")
set(DLL_HEADER_PATH  "${CMAKE_CURRENT_BINARY_DIR}/dll_data.h")

add_custom_command(
    OUTPUT  "${DLL_HEADER_PATH}"
    COMMAND "${CMAKE_COMMAND}"
            -DDLL_PATH="${DLL_OUTPUT_PATH}"
            -DHEADER_PATH="${DLL_HEADER_PATH}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/dll_to_header.cmake"
    DEPENDS DPSCounter_DLL
    COMMENT "Conversion dpscounter.dll → dll_data.h"
)

add_custom_target(DLL_Header ALL DEPENDS "${DLL_HEADER_PATH}")

# ======================================================
# EXE — DPSCounter_EXE (launcher)
# ======================================================
add_executable(DPSCounter_EXE WIN32
    src/dpscounter_main.cpp
)

add_dependencies(DPSCounter_EXE DLL_Header)

target_include_directories(DPSCounter_EXE PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}"   # dll_data.h généré ici
)

target_link_libraries(DPSCounter_EXE PRIVATE
    kernel32.lib
    user32.lib
    shell32.lib
)

target_compile_options(DPSCounter_EXE PRIVATE
    /W3
    /WX-
    /O2
    /MT
    /EHsc
    /DWIN32
    /D_WINDOWS
)

set_target_properties(DPSCounter_EXE PROPERTIES
    OUTPUT_NAME "DPSCounter"
    SUFFIX ".exe"
)

# ======================================================
# Message de résumé
# ======================================================
message(STATUS "Cibles: DPSCounter_DLL  →  dpscounter.dll")
message(STATUS "         DPSCounter_EXE  →  DPSCounter.exe")

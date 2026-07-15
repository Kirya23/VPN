cmake_minimum_required(VERSION 3.19)
project(VPN_client LANGUAGES CXX)  # Исправлено имя проекта

if(WIN32 AND MINGW AND NOT DEFINED OPENSSL_ROOT_DIR)
    set(_msys2_mingw_prefix "C:/msys64/mingw64")

    if(EXISTS "${_msys2_mingw_prefix}/include/openssl/evp.h"
       AND EXISTS "${_msys2_mingw_prefix}/lib/libcrypto.dll.a")
        set(OPENSSL_ROOT_DIR "${_msys2_mingw_prefix}" CACHE PATH "OpenSSL root directory")
        set(OPENSSL_INCLUDE_DIR "${_msys2_mingw_prefix}/include" CACHE PATH "OpenSSL include directory")
        set(OPENSSL_CRYPTO_LIBRARY "${_msys2_mingw_prefix}/lib/libcrypto.dll.a" CACHE FILEPATH "OpenSSL crypto library")
    endif()
endif()

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Network)
find_package(OpenSSL REQUIRED)

qt_standard_project_setup()

# Путь к папке с Wintun файлами
set(WINTUN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wintun")

# Включаем AUTOMOC
set(CMAKE_AUTOMOC ON)

qt_add_executable(VPN_cLeint
    main.cpp
    vpnclient.h
    vpnclient.cpp
    tunnelclient.h
    tunnelclient.cpp
    tunnelcrypto.h
    tunnelcrypto.cpp
    handshakeprotocol.h
    handshakeprotocol.cpp
    tunnelprotocol.h
    tunnelprotocol.cpp
    wintunadapter.h
    wintunadapter.cpp
)

target_include_directories(VPN_cLeint PRIVATE
    ${WINTUN_DIR}
)

target_link_libraries(VPN_cLeint  # И здесь то же имя
    PRIVATE
        Qt::Core
        Qt6::Network
        OpenSSL::Crypto
        ${CMAKE_DL_LIBS}
)

# Копируем wintun.dll
add_custom_command(TARGET VPN_cLeint POST_BUILD  # И здесь то же имя
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINTUN_DIR}/wintun.dll"
        $<TARGET_FILE_DIR:VPN_cLeint>
)

include(GNUInstallDirs)

install(TARGETS VPN_cLeint  # И здесь
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

cmake_minimum_required(VERSION 3.19)
project(VPN_server LANGUAGES CXX)

if(MSVC)
    add_compile_options(/utf-8)
else()
    add_compile_options(-finput-charset=UTF-8 -fexec-charset=UTF-8)
endif()

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Network)
find_package(OpenSSL REQUIRED)

qt_standard_project_setup()

qt_add_executable(VPN_server
    main.cpp
    vpnserver.h
    vpnserver.cpp
    tunnelprotocol.h
    tunnelprotocol.cpp
    handshakeprotocol.h
    handshakeprotocol.cpp
    linuxtundevice.h
    linuxtundevice.cpp
    tunnelcrypto.h
    tunnelcrypto.cpp
)

set(CMAKE_AUTOMOC ON)

target_link_libraries(VPN_server
    PRIVATE
        Qt::Core
        Qt6::Network
        OpenSSL::Crypto
)

include(GNUInstallDirs)

install(TARGETS VPN_server
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

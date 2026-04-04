cmake_minimum_required(VERSION 3.19)
project(VPN_server LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Network)

qt_standard_project_setup()

qt_add_executable(VPN_server
    main.cpp
    vpnserver.h vpnserver.cpp
)

set(set(CMAKE_AUTOMOC ON))

target_link_libraries(VPN_server
    PRIVATE
        Qt::Core
        Qt6::Network
)

include(GNUInstallDirs)

install(TARGETS VPN_server
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

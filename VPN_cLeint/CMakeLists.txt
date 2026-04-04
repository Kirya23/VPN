cmake_minimum_required(VERSION 3.19)
project(VPN_cLeint LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Network)

qt_standard_project_setup()

qt_add_executable(VPN_cLeint
    main.cpp
)

set(set(CMAKE_AUTOMOC ON))

target_link_libraries(VPN_cLeint
    PRIVATE
        Qt::Core
        Qt6::Network
)

include(GNUInstallDirs)

install(TARGETS VPN_cLeint
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

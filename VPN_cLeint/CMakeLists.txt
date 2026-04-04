cmake_minimum_required(VERSION 3.19)
project(VPN_client LANGUAGES CXX)  # Исправлено имя проекта

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Network)

qt_standard_project_setup()

# Путь к папке с Wintun файлами
set(WINTUN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wintun")

# Включаем AUTOMOC
set(CMAKE_AUTOMOC ON)

qt_add_executable(VPN_cLeint
    main.cpp
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

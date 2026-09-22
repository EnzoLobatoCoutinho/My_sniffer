cmake_minimum_required(VERSION 3.16)

project(my_sniffer VERSION 0.1.0 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    message(STATUS "Configuration cible : Windows")
    find_package(Npcap REQUIRED)
elseif(UNIX)
    message(STATUS "Configuration cible : Linux/Unix")
else()
    message(FATAL_ERROR "Systeme d'exploitation non supporte")
endif()

add_executable(my_sniffer
    src/main.cpp
    src/core/packet.cpp
    src/core/packet_builder.cpp
    src/core/event_bus.cpp
)

target_include_directories(my_sniffer
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(my_sniffer PRIVATE Npcap::Npcap)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
elseif(MSVC)
    add_compile_options(/W4 /WX)
endif()

if(WIN32)
    target_compile_definitions(my_sniffer PRIVATE MY_SNIFFER_WINDOWS=1)
elseif(UNIX)
    target_compile_definitions(my_sniffer PRIVATE MY_SNIFFER_LINUX=1)
endif()

include(CTest)

if(BUILD_TESTING)
    find_package(GTest CONFIG REQUIRED)

    add_executable(my_sniffer_tests
        tests/main.cpp
        tests/core/packet_test.cpp
        tests/core/packet_builder_test.cpp
        tests/core/event_bus_test.cpp
        src/core/packet.cpp
        src/core/packet_builder.cpp
        src/core/event_bus.cpp
    )

    target_include_directories(my_sniffer_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_link_libraries(my_sniffer_tests PRIVATE GTest::gtest_main)

    include(GoogleTest)
    gtest_discover_tests(my_sniffer_tests)
endif()
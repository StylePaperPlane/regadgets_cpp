cmake_minimum_required(VERSION 3.28)

project(regadgets_cpp VERSION 0.1.0 LANGUAGES CXX)

foreach(CONFIG Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER ${CONFIG} CONFIG_UPPER)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/${CONFIG})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/${CONFIG})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/${CONFIG})
endforeach()


include(CTest)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

option(REGADGETS_ENABLE_BASE2048 "Enable Base2048 support with custom table support" OFF)
option(REGADGETS_BUILD_EXAMPLES "Build example executables" ON)

file(GLOB_RECURSE REGADGETS_CPP_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(regadgets_cpp ${REGADGETS_CPP_SOURCES})
add_library(regadgets::regadgets_cpp ALIAS regadgets_cpp)

target_compile_features(regadgets_cpp PUBLIC cxx_std_23)

target_include_directories(regadgets_cpp
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(regadgets_cpp PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_STANDARD_REQUIRED ON
    EXPORT_NAME regadgets_cpp
)

if(MSVC)
    target_compile_options(regadgets_cpp PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(regadgets_cpp PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(REGADGETS_ENABLE_BASE2048)
    target_compile_definitions(regadgets_cpp PUBLIC REGADGETS_ENABLE_BASE2048=1)
endif()

if(REGADGETS_BUILD_EXAMPLES)
    add_executable(regadgets_demo examples/demo.cpp)
    target_link_libraries(regadgets_demo PRIVATE regadgets::regadgets_cpp)
endif()

if(BUILD_TESTING)
    add_executable(regadgets_smoke_tests tests/smoke_test.cpp)
    target_link_libraries(regadgets_smoke_tests PRIVATE regadgets::regadgets_cpp)
    add_test(NAME regadgets_smoke_tests COMMAND regadgets_smoke_tests)
endif()

if(MSVC)
    set_property(TARGET regadgets_cpp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

if(CMAKE_GENERATOR MATCHES "Visual Studio" AND TARGET regadgets_demo)
    set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT regadgets_demo)
endif()

install(
    TARGETS regadgets_cpp
    EXPORT regadgets_cppTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT regadgets_cppTargets
    NAMESPACE regadgets::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/regadgets_cpp
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/regadgets_cppConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/regadgets_cppConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/regadgets_cppConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/regadgets_cpp"
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/regadgets_cppConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/regadgets_cppConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/regadgets_cpp"
)

add_executable(my_app
        main.cpp)
target_link_libraries(my_app PRIVATE regadgets::regadgets_cpp)

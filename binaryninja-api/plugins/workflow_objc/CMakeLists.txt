cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(workflow_objc)

if(NOT BN_API_BUILD_EXAMPLES AND NOT BN_INTERNAL_BUILD)
    if(NOT BN_API_PATH)
        # If we have not already defined the API source directory try and find it.
        find_path(
                BN_API_PATH
                NAMES binaryninjaapi.h
                # List of paths to search for the clone of the api
                HINTS ../../.. ../../binaryninja/api/ binaryninjaapi binaryninja-api $ENV{BN_API_PATH}
                REQUIRED
        )
    endif()
    set(CARGO_STABLE_VERSION 1.83.0)
    add_subdirectory(${BN_API_PATH} binaryninjaapi)
endif()

file(GLOB_RECURSE PLUGIN_SOURCES CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/Cargo.toml
        ${PROJECT_SOURCE_DIR}/src/*.rs)

file(GLOB_RECURSE API_SOURCES CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/../../binaryninjacore.h
        ${PROJECT_SOURCE_DIR}/../../rust/binaryninjacore-sys/build.rs
        ${PROJECT_SOURCE_DIR}/../../rust/binaryninjacore-sys/Cargo.toml
        ${PROJECT_SOURCE_DIR}/../../rust/binaryninjacore-sys/src/*.rs
        ${PROJECT_SOURCE_DIR}/../../rust/Cargo.toml
        ${PROJECT_SOURCE_DIR}/../../rust/src/*/*.rs)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/debug)
    set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target)
else()
    set(TARGET_DIR ${PROJECT_BINARY_DIR}/target/release)
    set(CARGO_OPTS --target-dir=${PROJECT_BINARY_DIR}/target --release)
    set(OUTPUT_PDB_NAME ${CMAKE_SHARED_LIBRARY_PREFIX}workflow_objc.pdb)
endif()

set(OUTPUT_FILE ${CMAKE_STATIC_LIBRARY_PREFIX}workflow_objc${CMAKE_SHARED_LIBRARY_SUFFIX})
set(PLUGIN_PATH ${TARGET_DIR}/${OUTPUT_FILE})

add_custom_target(workflow_objc ALL DEPENDS ${PLUGIN_PATH})
add_dependencies(workflow_objc binaryninjaapi)

find_program(RUSTUP_PATH rustup REQUIRED HINTS ~/.cargo/bin)
if(CARGO_API_VERSION)
    set(RUSTUP_COMMAND ${RUSTUP_PATH} run ${CARGO_API_VERSION} cargo build)
else()
    set(RUSTUP_COMMAND ${RUSTUP_PATH} run ${CARGO_STABLE_VERSION} cargo build)
endif()

if(APPLE)
    if(UNIVERSAL)
        if(CMAKE_BUILD_TYPE MATCHES Debug)
            set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/debug/${OUTPUT_FILE})
            set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/debug/${OUTPUT_FILE})
        else()
            set(AARCH64_LIB_PATH ${PROJECT_BINARY_DIR}/target/aarch64-apple-darwin/release/${OUTPUT_FILE})
            set(X86_64_LIB_PATH ${PROJECT_BINARY_DIR}/target/x86_64-apple-darwin/release/${OUTPUT_FILE})
        endif()

        add_custom_command(
                OUTPUT ${PLUGIN_PATH}
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_CORE_OUTPUT_DIR}
                ${RUSTUP_COMMAND} --target=aarch64-apple-darwin ${CARGO_OPTS}
                COMMAND ${CMAKE_COMMAND} -E env
                MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_CORE_OUTPUT_DIR}
                ${RUSTUP_COMMAND} --target=x86_64-apple-darwin ${CARGO_OPTS}
                COMMAND mkdir -p ${TARGET_DIR}
                COMMAND lipo -create ${AARCH64_LIB_PATH} ${X86_64_LIB_PATH} -output ${PLUGIN_PATH}
                COMMAND ${CMAKE_COMMAND} -E copy ${PLUGIN_PATH} ${BN_CORE_PLUGIN_DIR}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
    else()
        if(CMAKE_BUILD_TYPE MATCHES Debug)
            set(LIB_PATH ${PROJECT_BINARY_DIR}/target/debug/${OUTPUT_FILE})
        else()
            set(LIB_PATH ${PROJECT_BINARY_DIR}/target/release/${OUTPUT_FILE})
        endif()

        add_custom_command(
                OUTPUT ${PLUGIN_PATH}
                COMMAND ${CMAKE_COMMAND} -E env MACOSX_DEPLOYMENT_TARGET=10.14 BINARYNINJADIR=${BN_CORE_OUTPUT_DIR} ${RUSTUP_COMMAND} ${CARGO_OPTS}
                COMMAND ${CMAKE_COMMAND} -E copy ${PLUGIN_PATH} ${BN_CORE_PLUGIN_DIR}
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
    endif()
elseif(WIN32)
    add_custom_command(
            OUTPUT ${PLUGIN_PATH}
            COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_CORE_OUTPUT_DIR} ${RUSTUP_COMMAND} ${CARGO_OPTS}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLUGIN_PATH} ${BN_CORE_PLUGIN_DIR}
            COMMAND ${CMAKE_COMMAND} -E copy ${TARGET_DIR}/${OUTPUT_PDB_NAME} ${BN_CORE_PLUGIN_DIR}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
else()
    add_custom_command(
            OUTPUT ${PLUGIN_PATH}
            COMMAND ${CMAKE_COMMAND} -E env BINARYNINJADIR=${BN_CORE_OUTPUT_DIR} ${RUSTUP_COMMAND} ${CARGO_OPTS}
            COMMAND ${CMAKE_COMMAND} -E copy ${PLUGIN_PATH} ${BN_CORE_PLUGIN_DIR}
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            DEPENDS ${PLUGIN_SOURCES} ${API_SOURCES})
endif()

cmake_minimum_required(VERSION 2.8.12)

# Set extension name here
set(TARGET_NAME azure)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
project(${TARGET_NAME})
include_directories(src/include)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(EXTENSION_SOURCES src/azure_extension.cpp)
add_library(${EXTENSION_NAME} STATIC ${EXTENSION_SOURCES})

set(PARAMETERS "-warnings")
build_loadable_extension(${TARGET_NAME} ${PARAMETERS} ${EXTENSION_SOURCES})

find_package(azure-identity-cpp CONFIG REQUIRED)
find_package(azure-storage-blobs-cpp CONFIG REQUIRED)

# Static lib
target_link_libraries(${EXTENSION_NAME} Azure::azure-identity Azure::azure-storage-blobs)
target_include_directories(${EXTENSION_NAME} PRIVATE Azure::azure-identity Azure::azure-storage-blobs)

# Loadable binary
target_link_libraries(${TARGET_NAME}_loadable_extension Azure::azure-identity Azure::azure-storage-blobs)
target_include_directories(${TARGET_NAME}_loadable_extension PRIVATE Azure::azure-identity Azure::azure-storage-blobs)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

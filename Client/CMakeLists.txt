cmake_minimum_required(VERSION 3.28.3)
project(Client)

# Найдем библиотеку OpenSSL
find_package(OpenSSL REQUIRED)

# Установим директорию для заголовочных файлов OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set(SERVER_SRC
    ${SRC_DIR}/main.cpp 
    ${SRC_DIR}/Client.cpp
    ${SRC_DIR}/RSAManager.cpp
    ${SRC_DIR}/Logger.cpp
)

include_directories(${INCLUDE_DIR})


add_executable(Client ${SERVER_SRC})
target_link_libraries(Client ${OPENSSL_LIBRARIES})

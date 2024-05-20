cmake_minimum_required(VERSION 3.28.3)
project(Server)

# Найдем библиотеку OpenSSL
find_package(OpenSSL REQUIRED)

# Установим директорию для заголовочных файлов OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

# Установка значения макроса OPENSSL_API_COMPAT
add_compile_definitions(OPENSSL_API_COMPAT=0x10100000L)

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set(SERVER_SRC
    ${SRC_DIR}/main.cpp 
    ${SRC_DIR}/Server.cpp
    ${SRC_DIR}/RSAManager.cpp
    ${SRC_DIR}/RSAManager.cpp
)

include_directories(${INCLUDE_DIR})

# Добавим библиотеки OpenSSL к нашему исполняемому файлу
add_executable(Server ${SERVER_SRC})
target_link_libraries(Server ${OPENSSL_LIBRARIES})

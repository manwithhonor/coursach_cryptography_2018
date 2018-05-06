cmake_minimum_required(VERSION 2.6)
project(server)

add_executable(server main.cpp debug.cpp)

target_compile_options(server PUBLIC "--std=c++11")

find_package(OpenSSL REQUIRED)

target_include_directories(server PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(server PUBLIC ${OPENSSL_LIBRARIES})

install(TARGETS server RUNTIME DESTINATION bin)

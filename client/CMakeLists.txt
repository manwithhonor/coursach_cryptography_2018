cmake_minimum_required(VERSION 2.6)
project(client)

add_executable(client main.cpp debug.cpp)

target_compile_options(client PUBLIC "--std=c++11")

find_package(OpenSSL REQUIRED)

target_include_directories(client PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(client PUBLIC ${OPENSSL_LIBRARIES})


install(TARGETS client RUNTIME DESTINATION bin)

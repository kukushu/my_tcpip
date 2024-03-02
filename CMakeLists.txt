cmake_minimum_required(VERSION 3.7)
project(net)
set(CMAKE_C_STANDARD 99)

LINK_DIRECTORIES(

)

add_compile_options(-g)

include_directories(
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/src/plat
)

file(GLOB_RECURSE SOURCE_LIST "src/*.c" "src/*.h")

add_executable(${PROJECT_NAME} ${SOURCE_LIST})

add_definitions(-DNET_DRIVER_PCAP)

target_link_libraries(${PROJECT_NAME} pthread pcap)


cmake_minimum_required(VERSION 2.8)

project(gtpu)

include_directories(
  ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/med
)

#set(CMAKE_LDFLAGS "${CMAKE_LDFLAGS} ")

# Library path
set(CMAKE_LDFLAGS "${CMAKE_LDFLAGS} -L\".\" ")

# Define the CXX sources
set ( CXX_SRCS
    ut/gtpu.cpp
)

set_source_files_properties(
    ${CXX_SRCS} PROPERTIES COMPILE_FLAGS 
    " -g -O3 -std=c++14 -Wall -Werror")

add_executable(gtest_gtpu ${CXX_SRCS})

target_link_libraries(gtest_gtpu
    gtest
)

enable_testing()
add_test(UT gtest_gtpu)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND}
                  DEPENDS gtest_gtpu)

cmake_minimum_required(VERSION 2.8)
project(gtpu)

enable_language(CXX)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-std=c++17" COMPILER_SUPPORTS_CXX17)
if (COMPILER_SUPPORTS_CXX17)
	add_definitions(-std=c++17)
else ()
	message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++17 support. Please use a different C++ compiler.")
endif ()

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

include_directories(
	${GTEST_INCLUDE_DIRS}
	${PROJECT_SOURCE_DIR}
	${PROJECT_SOURCE_DIR}/med
	${PROJECT_SOURCE_DIR}/med/med
)

# Library path
set(CMAKE_LDFLAGS
	"${CMAKE_LDFLAGS} -L\".\" "
)

# Define the CXX sources
set ( CXX_SRCS
	ut/gtpu.cpp
)

add_compile_options(
	-Werror
	-Wall
	-Wextra
	-Waddress
	-Warray-bounds
	-Winit-self
	-Wunreachable-code
	-pedantic
	-pedantic-errors
)

#set_source_files_properties(
#  ${CXX_SRCS} PROPERTIES COMPILE_FLAGS
#  " -g -O3 -std=c++14 -Wall -Werror"
#)

add_executable(gtest_gtpu
	${CXX_SRCS}
)

target_link_libraries(gtest_gtpu
	${GTEST_BOTH_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
)

if(DEFINED ENV{BUILD_FLAGS})
	set(BUILD_FLAGS "$ENV{BUILD_FLAGS}")
else ()
	set(BUILD_FLAGS "-O3")
endif ()

set_target_properties(gtest_gtpu PROPERTIES COMPILE_FLAGS
	${BUILD_FLAGS}
)

enable_testing()
add_test(UT gtest_gtpu)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND}
	DEPENDS gtest_gtpu)

cmake_minimum_required(VERSION 3.8)
project(TLSXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)

add_executable(opentls main.cpp include/tlsxx/hash/md5.hpp include/tlsxx/detail/iterator.hpp include/tlsxx/detail/bit.hpp)

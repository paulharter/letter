cmake_minimum_required(VERSION 4.0)
project(letter C)

set(CMAKE_C_STANDARD 90)

add_library(letter STATIC library.c)

cmake_minimum_required(VERSION 3.8.0)
project(CLRPEPatcher VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


file(GLOB clrpepatcher_src CONFIGURE_DEPENDS "./src/*.h" "./src/*.cpp")


add_executable(CLRPEPatcher ${clrpepatcher_src})

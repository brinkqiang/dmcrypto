cmake_minimum_required(VERSION 3.21)

PROJECT(dmcrypto)

LIST(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
INCLUDE(cmake/ModuleImport.cmake)
INCLUDE(cmake/ModuleCompileOptions.cmake)
ModuleSetCompileOptions()
ModuleSetWinCompilerFlags()


LibImport("dmcrypto" "src/dmcrypto")

IF(PROJECT_IS_TOP_LEVEL)
    ModuleImport("dmtest" "thirdparty/dmtest")
    ExeImport("test" "dmcrypto;dmtest")
ENDIF()



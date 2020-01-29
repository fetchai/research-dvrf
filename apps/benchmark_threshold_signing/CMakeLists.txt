###################################################################################
# B E N C H M A R K   T H R E S H O L D   S I G N I N G   A P P
###################################################################################
# CMake build : main application

#configure variables
set (APP_NAME "BenchmarkThresholdSigning")

#configure directories
set (APP_MODULE_PATH "${PROJECT_SOURCE_DIR}/apps/benchmark_threshold_signing")
set (APP_SRC_PATH  "${APP_MODULE_PATH}/src" )

#set target executable
add_executable (${APP_NAME} "${APP_SRC_PATH}/main.cpp")

#set includes
target_include_directories (${APP_NAME} PRIVATE ${THIRD_PARTY_INCLUDE_PATH})

#add the library
target_link_libraries (${APP_NAME} ${LIB_NAME} Threads::Threads)
################################################################################
# N E T W O R K   A P P
################################################################################
# CMake build : main application

#configure variables
set (APP_NAME "Network")

#configure directories
set (APP_MODULE_PATH "${PROJECT_SOURCE_DIR}/apps/network")
set (APP_SRC_PATH  "${APP_MODULE_PATH}/src" )

#set target executable
add_executable (${APP_NAME} "${APP_SRC_PATH}/main.cpp")

#set includes
target_include_directories (${APP_NAME} PRIVATE ${THIRD_PARTY_INCLUDE_PATH})

#add the library
target_link_libraries (${APP_NAME} ${LIB_NAME} Threads::Threads)



################################################################################
# R A N D O M   B E A C O N
################################################################################
# CMake build : main application

#configure variables
set (APP_NAME "RandomBeacon")

#configure directories
set (APP_MODULE_PATH "${PROJECT_SOURCE_DIR}/apps/random_beacon")
set (APP_SRC_PATH  "${APP_MODULE_PATH}/src" )

#set target executable
add_executable (${APP_NAME} "${APP_SRC_PATH}/main.cpp")

#set includes
target_include_directories (${APP_NAME} PRIVATE ${THIRD_PARTY_INCLUDE_PATH})

#add the library
target_link_libraries (${APP_NAME} ${LIB_NAME} Threads::Threads)

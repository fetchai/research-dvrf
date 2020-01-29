#configure variables
set (APP_NAME "Client")

#configure directories
set (APP_MODULE_PATH "${PROJECT_SOURCE_DIR}/apps/client_server/client")

#set target executable
add_executable (${APP_NAME} "${APP_MODULE_PATH}/main.cpp")

#set includes
target_include_directories (${APP_NAME} PRIVATE ${THIRD_PARTY_INCLUDE_PATH})

#add the library
target_link_libraries (${APP_NAME} ${LIB_NAME} Threads::Threads)



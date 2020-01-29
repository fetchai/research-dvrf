################################################################################
# T E S T S
################################################################################
# CMake build : library tests

#configure variables
set (TEST_APP_NAME "${LIB_NAME}Test")

#configure directories
set (TEST_MODULE_PATH "${LIBRARY_MODULE_PATH}/test")
set (TEST_SRC_PATH  "${TEST_MODULE_PATH}/src" )

#set test sources
file (GLOB TEST_SOURCE_FILES "${TEST_SRC_PATH}/*.cpp")

#set target executable
add_executable (${TEST_APP_NAME} ${TEST_SOURCE_FILES})

#add the library
target_include_directories(${TEST_APP_NAME} PRIVATE ${TEST_THIRD_PARTY_INCLUDE_PATH})
target_link_libraries (${TEST_APP_NAME} ${LIB_NAME} Threads::Threads)

# Turn on CMake testing capabilities
enable_testing()

#parse catch tests
ParseAndAddCatchTests (${TEST_APP_NAME})

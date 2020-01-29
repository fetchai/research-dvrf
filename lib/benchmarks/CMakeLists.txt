################################################################################
# B E N C H M A R K S
################################################################################
# CMake build : library tests

#configure variables
set (APP_NAME "${LIB_NAME}Benchmarks")

#configure directories
set (MODULE_PATH "${LIBRARY_MODULE_PATH}/benchmarks")

#configure test directories
set (SRC_PATH  "${MODULE_PATH}/src" )

#set includes
include_directories (${LIBRARY_INCLUDE_PATH} ${TEST_THIRD_PARTY_INCLUDE_PATH})

#set test sources
file (GLOB SOURCE_FILES "${SRC_PATH}/*.cpp")

#set target executable
add_executable (${APP_NAME} ${SOURCE_FILES})

#add the library
target_link_libraries (${APP_NAME} ${LIB_NAME} Threads::Threads)

# Turn on CMake testing capabilities
enable_testing()

#parse catch tests
ParseAndAddCatchTests (${APP_NAME})
find_package(Protobuf REQUIRED)

PROTOBUF_GENERATE_CPP(PROTO_SRC PROTO_HEADER proto/consensus.proto)

add_library(proto ${PROTO_HEADER} ${PROTO_SRC})
target_link_libraries(proto PUBLIC protobuf::libprotobuf)

# CMake build : library

#configure variables
set(LIB_NAME "${PROJECT_NAME}")
set(LIB_CONFIG "${LIB_NAME}LibConfig")

#configure directories
set(LIBRARY_MODULE_PATH "${PROJECT_SOURCE_DIR}/lib")
set(LIBRARY_SRC_PATH "${LIBRARY_MODULE_PATH}/src")
set(LIBRARY_INCLUDE_PATH "${LIBRARY_MODULE_PATH}/include")

#set sources
file(GLOB LIB_HEADER_FILES "${LIBRARY_INCLUDE_PATH}/*.hpp")
file(GLOB LIB_SOURCE_FILES "${LIBRARY_SRC_PATH}/*.cpp")

#set library
add_library(${LIB_NAME} ${LIB_HEADER_FILES} ${LIB_SOURCE_FILES})

target_include_directories(${LIB_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${CMAKE_CURRENT_BINARY_DIR}
        ${THIRD_PARTY_INCLUDE_PATH})

target_link_libraries(${LIB_NAME} PUBLIC sodium ${GMP_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto libmcl noise_protocol librelic proto)

set(LIBRARY_INCLUDE_PATH ${LIBRARY_INCLUDE_PATH} PARENT_SCOPE)
set(LIB_NAME ${LIB_NAME} PARENT_SCOPE)

#install(TARGETS ${LIB_NAME} EXPORT ${LIB_CONFIG}
#    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT library
#    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT library
#    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT library
#)
#set (PROTO_HEADER_FILES "${CMAKE_CURRENT_BINARY_DIR}/consensus.pb.h")
#message("Proto file ${PROTO_HEADER_FILES}")
#install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${LIB_NAME})
#install(DIRECTORY proto DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${LIB_NAME})
#install(FILES ${PROTO_HEADER_FILES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${LIB_NAME})
#install(EXPORT ${LIB_CONFIG} DESTINATION cmake)

# this makes the project importable from the build directory.
#export(TARGETS ${LIB_NAME} FILE "${LIB_CONFIG}.cmake")

#test
enable_testing()
add_subdirectory(test)
add_subdirectory(benchmarks)

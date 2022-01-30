cmake_minimum_required(VERSION 3.15)

project(MyTool)
set(CMAKE_CXX_STANDARD 14)


add_subdirectory(thirdparty/capstone)


get_target_property(CAPSTONE_SHARED_OUTPUT_NAME capstone-shared OUTPUT_NAME)
get_target_property(CAPSTONE_SHARED_IMPORT_SUFFIX capstone-shared IMPORT_SUFFIX)
set(CS_LIB_NAME ${CAPSTONE_SHARED_OUTPUT_NAME}${CAPSTONE_SHARED_IMPORT_SUFFIX})
message(STATUS "CS_LIB_NAME:" ${CS_LIB_NAME})

get_target_property(CAPSTONE_INCLUDE_DIR capstone-shared INCLUDE_DIRECTORIES)
message(STATUS "CS_INC_DIR: "${CAPSTONE_INCLUDE_DIR})

set(SRC main.cpp)

include_directories(${CAPSTONE_INCLUDE_DIR} ${CMAKE_CURRENT_LIST_DIR}/include)
add_executable(${PROJECT_NAME} ${SRC})
target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_LIST_DIR}/lib/${CS_LIB_NAME})


add_custom_command(
    TARGET ${PROJECT_NAME}
    PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_LINKER_FILE:capstone-shared> ${CMAKE_CURRENT_LIST_DIR}/lib/$<TARGET_LINKER_FILE_NAME:capstone-shared>
    COMMAND ${CMAKE_COMMAND} -E echo "Copied $<TARGET_LINKER_FILE:capstone-shared> to ${CMAKE_CURRENT_LIST_DIR}/lib"
    VERBATIM
)

add_custom_command(
    TARGET ${PROJECT_NAME}
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:capstone-shared> $<TARGET_FILE_DIR:${PROJECT_NAME}>
    COMMAND ${CMAKE_COMMAND} -E echo "copied dll to $<TARGET_FILE_DIR:${PROJECT_NAME}>"
    VERBATIM
)
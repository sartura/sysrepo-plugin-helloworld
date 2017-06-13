CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
set(CMAKE_INSTALL_LIBDIR "/usr/lib")

project(sysrepo-plugin-dt-helloworld)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build) #

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_C_FLAGS "-std=gnu99")
set(SOURCES
	src/helloworld.c)

if(CMAKE_BUILD_TYPE MATCHES "debug")
  add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
  target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE DEBUG=1)
  install(TARGETS ${CMAKE_PROJECT_NAME}
	  DESTINATION lib/sysrepo/plugins)
else()
  add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
  install(TARGETS ${CMAKE_PROJECT_NAME} LIBRARY
	  DESTINATION lib/sysrepo/plugins)
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_PROJECT_NAME} PREFIX "")

find_package(UCI REQUIRED)
include_directories(${UCI_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${UCI_LIBRARIES})

find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

install(
	FILES
		yang/helloworld@2017-06-07.yang
	DESTINATION etc/yang/
)

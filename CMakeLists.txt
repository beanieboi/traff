cmake_minimum_required(VERSION 4.2)
project(Traff)

set(TRAFF_MAJOR_VERSION 0)
set(TRAFF_MINOR_VERSION 7)
set(TRAFF_PATCH_VERSION 0)
set(TRAFF_VERSION
  ${TRAFF_MAJOR_VERSION}.${TRAFF_MINOR_VERSION}.${TRAFF_PATCH_VERSION})

set(TRAFF_OPT_LIBS)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

find_package(PCAP REQUIRED)
set(TRAFF_OPT_LIBS ${TRAFF_OPT_LIBS} ${PCAP_LIBRARIES})

option(WITH_MYSQL "Support MYSQL database dumping" off)
option(WITH_PSQL "Support PostgreSQL database dumping" off)

if(WITH_MYSQL)
  find_package(MYSQL REQUIRED)
  set(TRAFF_OPT_LIBS ${TRAFF_OPT_LIBS} ${MYSQL_LIBRARIES})
endif(WITH_MYSQL)

if(WITH_PSQL)
  find_package(POSTGRESQL REQUIRED)
  set(TRAFF_OPT_LIBS ${TRAFF_OPT_LIBS} ${PostgreSQL_LIBRARY})
endif(WITH_PSQL)

SET(traff_SRCS
   traff.c
   ip_table.c
   readconfig.c
)

add_executable(traff ${traff_SRCS})
target_link_libraries(traff ${TRAFF_OPT_LIBS})
install(TARGETS traff DESTINATION bin)

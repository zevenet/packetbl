###############################################################################
#
#    Zevenet Load Balancer Software License
#    This file is part of the Zevenet zproxy Load Balancer software package.
#
#    Copyright (C) 2019-today ZEVENET SL, Sevilla (Spain)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

cmake_minimum_required(VERSION 3.7)
set(CMAKE_CXX_STANDARD 17)

project(packetbl)

SET(PROJECT_VERSION "0.10.0")

SET(MAINFOLDER ${PROJECT_SOURCE_DIR})
SET(CONFIGDIR "${PREFIX}/etc")
SET(CONFIGFILE "${SYSCONFDIR}/packetbl.conf")



#packetbl_CFLAGS = ${PTHREAD_CFLAGS}
#${PTHREAD_LIBS}

option(ENABLE_CACHE "It creates a cache in order to save the blocked IPs a while " ON)
option(ENABLE_FIREDNS "It is a library to do requests in parallel to reduce the resolution time " OFF)


if (ENABLE_CACHE)
    add_definitions(-DUSE_CACHE)
endif()
if (ENABLE_FIREDNS)
    add_definitions(-DHAVE_FIREDNS)
endif()

add_definitions(-DPACKAGE_VERSION="${PROJECT_VERSION}")
add_definitions(-DCONFIGFILE="${CONFIGFILE}")

# FIXME:  Link with version 0 for previous debian version
add_definitions(-DNETFILTERQUEUE_VERSION_NUMBER=1)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lresolv -ldl -g -rdynamic  -lm ")
set(CMAKE_C_FLAGS_DEBUG "-g -rdynamic ")

# libdotconf0, libldns2, libnetfilter-queue1, libnfnetlink0
# debian dirs
include_directories(/usr/include)
include_directories(/usr/include/linux/stddef.h)
link_directories(/usr/lib/x86_64-linux-gnu)


add_executable(${PROJECT_NAME}
                src/packetbl.c
                src/packetbl.h
                src/directresolv.h
)

# ctype.h errno.h getopt.h netdb.h netinet/in.h netinet/tcp.h regex.h stdarg.h stdint.h stdio.h stdlib.h string.h string.h syslog.h sys/stat.h sys/types.h time.h unistd.h unistd.h
target_link_libraries(${PROJECT_NAME} -lnetfilter_queue -lnfnetlink -ldotconf -lldns -pthread)

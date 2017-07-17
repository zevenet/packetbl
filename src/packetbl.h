#ifndef LOCAL_PACKETBL_H
#  define LOCAL_PACKETBL_H

#  ifdef HAVE_CONFIG_H
#    include "config.h"
#  endif

#  ifdef USE_SOCKSTAT
#    ifndef SOCKSTAT_PATH
#      define SOCKSTAT_PATH "/tmp/.packetbl.sock"
#    endif
#  endif

#endif

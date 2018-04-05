project(Bro-Plugin-FIX4_FIXT)

cmake_minimum_required(VERSION 2.8)
add_definitions("-std=c++11")

if ( NOT BRO_DIST )
    message(FATAL_ERROR "BRO_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

include(BroPlugin)

bro_plugin_begin(Bro FIX4_FIXT)
bro_plugin_cc(src/Plugin.cc)
bro_plugin_cc(src/FIX.cc)
bro_plugin_bif(src/events.bif)
bro_plugin_pac(src/fix.pac src/fix-analyzer.pac src/fix-protocol.pac)
bro_plugin_end()

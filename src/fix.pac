# Copyright 2018 Reservoir Labs

# Analyzer for Financial Information eXchange (ASCII)
#  - fix-protocol.pac: describes the FIX protocol messages
#  - fix-analyzer.pac: describes the FIX analyzer code

%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

# Analyzer definition
analyzer FIX4_FIXT withcontext {
	connection: FIX_Conn;
	flow:       FIX_Flow;
};

# Connection definition
connection FIX_Conn(bro_analyzer: BroAnalyzer) {
	# The connection consists of two flows, one for each direction.
	upflow   = FIX_Flow(true);
	downflow = FIX_Flow(false);
};

%include fix-protocol.pac

# Flow definition
flow FIX_Flow(is_orig: bool) {

	# Using flowunit will cause the anlayzer to buffer incremental input.
	# This is needed for &oneline and &length. If this is not needed, use
	# datagram to achieve better performance

	flowunit = FIX_PDU(is_orig) withcontext(connection, this);

};

%include fix-analyzer.pac


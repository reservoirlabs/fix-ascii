// Copyright 2018 Reservoir Labs

#include "FIX.h"

#include "analyzer/protocol/tcp/TCP_Reassembler.h"

#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::FIX4_FIXT;

FIX_Analyzer::FIX_Analyzer(Connection* c)

: tcp::TCP_ApplicationAnalyzer("FIX4_FIXT", c)

	{
	interp = new binpac::FIX4_FIXT::FIX_Conn(this);
	
	had_gap = false;
	
	}

FIX_Analyzer::~FIX_Analyzer()
	{
	delete interp;
	}

void FIX_Analyzer::Done()
	{
	
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	
	}

void FIX_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void FIX_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void FIX_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

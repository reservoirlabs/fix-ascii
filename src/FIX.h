// Copyright 2018 Reservoir Labs

#ifndef ANALYZER_PROTOCOL_FIX_FIX_H
#define ANALYZER_PROTOCOL_FIX_FIX_H

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"

#include "fix_pac.h"

namespace analyzer { namespace FIX4_FIXT {

class FIX_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	FIX_Analyzer(Connection* conn);
	virtual ~FIX_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new FIX_Analyzer(conn); }

protected:
	binpac::FIX4_FIXT::FIX_Conn* interp;
	
	bool had_gap;
	
};

} } // namespace analyzer::* 

#endif

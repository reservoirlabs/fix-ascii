# Copyright 2018 Reservoir Labs

##! Implements base functionality for FIX analysis.
##! Generates the fix.log file.

module Fix;

export {
	redef enum Log::ID += { LOG };

	type Type: enum {
		## Type used for a generic FIX record (used this type if there is no other more specific type)
		FixMessage,
		## A potential FIX connection failed to comply with the FIX protocol specification 
		ValidationFailed,
		## A logon request
		FixLogonReq,
		## A logon response
		FixLogonRes,
		## A FIX reject
		FixReject,
	};		

	type Info: record {
		ts: time               &log;           ## Timestamp for when the event happened.
		uid: string            &log;           ## Unique ID for the connection.  
		id: conn_id            &log;           ## The connection's 4-tuple of endpoint addresses/ports.
		rec_type: Type         &log;           ## The Fix::Type of this FIX record 
                beginstring: string    &log;           ## BeginString field (key = 8 | mandatory) 
		bodylength: string     &log &optional; ## BodyLength field (key = 9 | mandatory)
		msgtype: string        &log &optional; ## MsgType field (key = 35 | mandatory)
		sendercompid: string   &log &optional; ## SenderCompID field (key = 49 | mandatory since FIXT.1.1 / FIX.5.0)
		targetcompid: string   &log &optional; ## TargetCompID field (key = 56 | mandatory since FIXT.1.1 / FIX.5.0)
		checksum: string       &log &optional; ## Checksum field (key = 10 | mandatory)
		checksum_correct: bool &log &optional; ## True if checksum is correct, false otherwise
		note: string           &log &optional; ## Used to write additional notes on a FIX record
		# Other internal per-context state not to be logged
		analyzer_id: count     &optional;      ## The ID of the FIX analyzer processing this connection
		disabled_aids: set[count] &optional;   ##  Track if analyzer was disabled to avoid disabling it again
	};

	## Event that can be handled to access the FIX record as it is sent on
	## to the loggin framework.
	global log_fix: event(rec: Info);
}


# Add a fix context to the connection record
redef record connection += {
        fix: Info &optional;
};


# There is no IANA standard port number for the FIX protocol.
# While setting this variable is not mandatory since we rely on DPD to attach the FIX
# analyzer to a connection, if in your specific configuration you have a
# port number associated with your FIX service, you can add it here. This will allow
# you to detect misuses of this port number. Make sure you also enable the call to
# Analyzer::register_for_ports in bro_init.
# Example: 
# const ports : set[port] = { 1234/tcp, 5678/tcp };
const ports : set[port] = { };
redef likely_server_ports += { ports };


event bro_init() &priority=5
	{
	Log::create_stream(Fix::LOG, [$columns=Info, $ev=log_fix, $path="fix"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_FIX4_FIXT, ports);
	}

event fix_detected(c: connection,
                   beginstring: string) 
	{
	# The message first bytes (up to the BeginString field) were correctly
	# parsed. Consider this a connection detected as FIX. Notice
	# that this does not mean the message has been validated
	# as being fully FIX compliant. If the message is not compliant,
	# a FIX record in fix.log will be reported of type ValidationFailed.
	add c$service["fix"];
	}

event fix_message(c: connection, 
                  beginstring: string,
                  bodylength: string,
                  msgtype: string,
                  sendercompid: string,
                  targetcompid: string,
                  checksum: string,
                  checksum_correct: bool,
                  is_orig: bool)
	{
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	# Derive the FIX record type 
	if (strcmp(msgtype, "A") == 0) 
		{
		if (is_orig)
			info$rec_type = FixLogonReq;
		else
			info$rec_type = FixLogonRes;
		event fix_logon(c, sendercompid, targetcompid);
		}
	else if (strcmp(msgtype, "3") == 0) 
		{
		info$rec_type = FixReject;
		event fix_reject(c, sendercompid, targetcompid);
		}
	else 
		{
		# None of the above, set it as a general FIX message
		info$rec_type = FixMessage;
		}

        info$beginstring = beginstring;
        info$bodylength = bodylength;
        info$msgtype = msgtype;
        info$sendercompid = sendercompid;
        info$targetcompid = targetcompid;
        info$checksum = checksum;
        info$checksum_correct = checksum_correct;
	Log::write(Fix::LOG, info);

	# Since we have already validated that one FIX message in this connection
	# complies, we can disable the analyzer for this connection
	# if the analyzer ID was already populated by protocol_confirmation()
	if (c?$fix && c$fix?$analyzer_id && (c$fix$analyzer_id !in c$fix$disabled_aids))
		{
		disable_analyzer(c$id, c$fix$analyzer_id);
		add c$fix$disabled_aids[c$fix$analyzer_id];
		}
	}

function set_session(c: connection)
	{
	if (!c?$fix)
		{
		# Allocate a new fix record
		local info: Fix::Info;
		c$fix = info;
		c$fix$disabled_aids = set(); 
		}
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) 
        {
        if (atype == Analyzer::ANALYZER_FIX4_FIXT)
                {
		set_session(c);
                c$fix$analyzer_id = aid;
                }
        }

event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count, reason: string) 
	{
	if (atype != Analyzer::ANALYZER_FIX4_FIXT)	
		return;
	# Set context if it has not been set yet
	set_session(c);
	# Don't disable the analyzer if it was already disabled
	if (aid in c$fix$disabled_aids)
		return;
	# A connection detected as FIX has a protocol non-compliant message, report it and disable the analyzer
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;
	info$rec_type = ValidationFailed; 
	# Generic note 
	local fix_reason = "Failed to parse non-compliant FIX message";
	# Try to get a more specific note by pasing the reason parameter and sanitizing it
	if ("expcted pattern" in reason)
		fix_reason = fmt("Expected pattern%s", split_string(reason, /expected pattern/)[1]);
	if ("actual data" in reason)
		fix_reason =  sub(fix_reason, /actual data/, " Actual data");
	info$note = fix_reason;
	Log::write(Fix::LOG, info);

	# Disable analyzer
	disable_analyzer(c$id, aid);
	add c$fix$disabled_aids[aid];
	}


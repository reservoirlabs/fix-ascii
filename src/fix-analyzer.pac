# Copyright 2018 Reservoir Labs

# Analyzer specification

%header{

#define FOR_CSUM(csum, data, len) for(long idx = 0; idx < len; csum += (unsigned int)data[idx++])

static unsigned int fix_field_checksum(const_bytestring const tag,
                                       const_bytestring const equal,
                                       const_bytestring const value,
                                       const bytestring delimiter, 
                                       bool trimtag,
                                       unsigned int csum_in) {
	// Performs incremental checksum of a FIX field without taking modulo 256 
	// to allow computation to be iteratively fed
	long idx;
	unsigned int csum_out = csum_in;
	FOR_CSUM(csum_out, tag.begin(), tag.length() - (trimtag? 1 : 0));
	FOR_CSUM(csum_out, equal.begin(), equal.length());
	FOR_CSUM(csum_out, value.begin(), value.length());
	FOR_CSUM(csum_out, delimiter.begin(), delimiter.length());
	return csum_out;
}

static unsigned int fix_checksum(FIX_PDU *msg) {

        // Algorithm taken from the FIX specification "FINANCIAL 
        // INFORMATION EXCHANGE PROTOCOL (FIX) Version 4.4"

	unsigned int csum = 0;
	FIX_HEADER *header = msg->header();
	FIX_BODY *body = msg->body();

	// Checksum the header 
	csum = fix_field_checksum(header->beginstring()->tag(),
	                          bytestring((unsigned char*)"=", 1),
	                          header->beginstring()->value(),
	                          bytestring((unsigned char*)"\x001", 1),
	                          true,
	                          csum);
	csum = fix_field_checksum(header->bodylength()->tag(),
	                          bytestring((unsigned char*)"=", 1),
	                          header->bodylength()->value(),
	                          bytestring((unsigned char*)"\x001", 1),
	                          true,
	                          csum);
	csum = fix_field_checksum(header->msgtype()->tag(),
	                          bytestring((unsigned char*)"=", 1),
	                          header->msgtype()->value(),
	                          bytestring((unsigned char*)"\x001", 1),
	                          true,
	                          csum);

	// Checksum the body without including the checksum field itself
	for (unsigned int i = 0; i < msg->body()->fields()->size(); i++) {
		csum = fix_field_checksum((*(body->fields()))[i]->tag(),
		                          (*(body->fields()))[i]->equal(),
	        	                  (*(body->fields()))[i]->value(),
	        	                  (*(body->fields()))[i]->delimiter(),
		                          false,
	                        	  csum);
	} 

	// Modulo 256
	csum = csum % 256;
	return csum;
}

%}

# Extend the FIX flow with additional analysis capabilities
refine flow FIX_Flow += {
	function proc_fix_message(msg: FIX_PDU, is_orig: bool): bool
		%{
		FIX_HEADER *header = msg->header();
		FIX_BODY *body = msg->body();

		// Perform checksum
		unsigned int csum = fix_checksum(msg);

		// Extract the checksum field from the message
		bytestring csum_bs = body->cksum()->value(); 
		unsigned int csum_msg_uint = (unsigned int)bytestring_to_int(csum_bs, 10); 

		// Extract the following extra fields from the rest of the body fields:
		//    - SenderCompID
		//    - TargetCompIP
		StringVal *sender_comp_id = NULL;
		StringVal *target_comp_id = NULL;
		for (unsigned int i = 0; i < msg->body()->fields()->size(); i++) {
			if (bytestring_to_int((*(body->fields()))[i]->tag(), 10) == 49)
				sender_comp_id = bytestring_to_val((*(body->fields()))[i]->value());
			if (bytestring_to_int((*(body->fields()))[i]->tag(), 10) == 56)
				target_comp_id = bytestring_to_val((*(body->fields()))[i]->value());
		}

		// Pass the metadata to fix_message so it can be processed in scriptland
		BifEvent::generate_fix_message(connection()->bro_analyzer(),                       // Analyzer 
		                               connection()->bro_analyzer()->Conn(),               // Connection
		                               bytestring_to_val(header->beginstring()->value()),  // BeginString
		                               bytestring_to_val(header->bodylength()->value()),   // BodyLength
		                               bytestring_to_val(header->msgtype()->value()),      // MsgType 
		                               sender_comp_id,                                     // SenderCompID 
		                               target_comp_id,                                     // TargetCompID 
		                               bytestring_to_val(csum_bs),                         // Checksum
		                               csum == csum_msg_uint,                              // Checksum correct?
		                               is_orig);                                           // Message from originator?
		return true;
		%}
};

refine typeattr FIX_PDU += &let {
	# If we are here we know we were able to correctly parse the PDU,
	# so this is a valid FIX message (except for checksum validation). 
	# Report it upstream.
	proc: bool = $context.flow.proc_fix_message(this, is_orig);
};


# Copyright 2018 Reservoir Labs

# Protocol specification

refine connection FIX_Conn += {

        function proc_fix_detected(header: FIX_HEADER): bool
        %{
                BifEvent::generate_fix_detected(bro_analyzer(), bro_analyzer()->Conn(), bytestring_to_val(header->beginstring()->value()));
                return true;
        %}

	function fix_body_length(header: FIX_HEADER): int
	%{ 
		// According to the FIX SESSION PROTOCOL specification:
		// "The message length is indicated in the BodyLength field and 
		//  is verified by counting the number of characters in the message 
		//  following the BodyLength field up to, and including, the delimiter 
		//  immediately preceding the CheckSum tag ('10=')."
		int len;
		len  = bytestring_to_int(header->bodylength()->value(), 10);
		// Subtract the length of the rest of the fields in the FIX_HEADER, 
		// which includes:
		//     - MsgType
		len -= header->msgtype()->tag().length(); 
		len -= header->msgtype()->value().length(); 
		len -= 1;  // End of field delimiter
		return len;
	%}

};

# Types for parsing FIX tag=value fields
type FIX_FIELD_BEGINSTRING_TAG = RE/8=/;  # Tag for the BeginString field
type FIX_FIELD_BODYLENGTH_TAG = RE/9=/;   # Tag for the BodyLength field
type FIX_FIELD_MSGTYPE_TAG = RE/35=/;     # Tag for the MsgType field
type FIX_FIELD_CSUM_TAG = RE/10=/;     # Tag for the MsgType field
type FIX_FIELD_VALUE = RE/[^\x01]*/;      # The value of a field
type FIX_FIELD_DELIMITER = RE/\x01/;      # The delimiter of a field

type FIX_FIELD_BEGINSTRING = record {
	tag: FIX_FIELD_BEGINSTRING_TAG;            
	value: FIX_FIELD_VALUE;
};

type FIX_FIELD_BODYLENGTH = record {
	tag: FIX_FIELD_BODYLENGTH_TAG;            
	value: FIX_FIELD_VALUE;
};

type FIX_FIELD_MSGTYPE = record {
	tag: FIX_FIELD_MSGTYPE_TAG;            
	value: FIX_FIELD_VALUE;
};

type FIX_FIELD_CSUM = record {
	tag: FIX_FIELD_CSUM_TAG;            
	value: FIX_FIELD_VALUE;
};

# Generic field
type FIX_FIELD = record {         # Generic field record
	tag: RE/[^=]*/;                # The tag
	equal: RE/=/;                  # "=" tag/value delimiter
	value: RE/[^\x01]*/;           # The value
	delimiter: RE/\x01/;           # "\x01" end of field delimited
};

type FIX_HEADER = record {
	# Mandatory fields for all FIX versions
	# BeginString field
	beginstring: FIX_FIELD_BEGINSTRING &oneline &linebreaker="\001" &let {
                proc_detected: bool = $context.connection.proc_fix_detected(this);
        };
	# BodyLength field
	bodylength: FIX_FIELD_BODYLENGTH &oneline &linebreaker="\001";
	# MsgType field
	msgtype: FIX_FIELD_MSGTYPE &oneline &linebreaker="\001";
} &let {
	body_length: int = $context.connection.fix_body_length(this); 
};

type FIX_BODY(body_length: int) = record {
	# The rest of the fields up to (but not including) the checksum field
	fields: FIX_FIELD[] &length=body_length;
	# Checksum
	cksum: FIX_FIELD_CSUM &oneline &linebreaker="\001";
};

# Definition of the FIX PDU
type FIX_PDU(is_orig: bool) = record {
	header: FIX_HEADER;
	body: FIX_BODY(header.body_length);
} &byteorder=bigendian;


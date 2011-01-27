// L2TPNS: constants

#include <stdio.h>
#include "constants.h"

#define CONSTANT(table, ...) \
    static char const *table ## s[] = { \
	__VA_ARGS__ \
    }; \
    char const *table(int index) \
    { \
	static char n[16]; \
	if (index >= 0 && index < sizeof(table ## s) / sizeof(table ## s[0]) \
	    && table ## s[index]) \
		return table ## s[index]; \
	snprintf(n, sizeof(n), "%d", index); \
	return n; \
    }

CONSTANT(l2tp_code,
    0,							// 0
    "SCCRQ",						// 1
    "SCCRP",						// 2
    "SCCCN",						// 3
    "StopCCN",						// 4
    0,							// 5
    "HELLO",						// 6
    "OCRQ",						// 7
    "OCRP",						// 8
    "OCCN",						// 9
    "ICRQ",						// 10
    "ICRP",						// 11
    "ICCN",						// 12
    0,							// 13
    "CDN",						// 14
    "WEN",						// 15
    "SLI"						// 16
)

CONSTANT(l2tp_avp_name,
    "Message Type",					// 0
    "Result Code",					// 1
    "Protocol Version",					// 2
    "Framing Capabilities",				// 3
    "Bearer Capabilities",				// 4
    "Tie Breaker",					// 5
    "Firmware Revision",				// 6
    "Host Name",					// 7
    "Vendor Name",					// 8
    "Assigned Tunnel ID",				// 9
    "Receive Window Size",				// 10
    "Challenge",					// 11
    "Q.931 Cause Code",					// 12
    "Challenge Response",				// 13
    "Assigned Session ID",				// 14
    "Call Serial Number",				// 15
    "Minimum BPS",					// 16
    "Maximum BPS",					// 17
    "Bearer Type",					// 18 (2 = Analog, 1 = Digital)
    "Framing Type",					// 19 (2 = Async, 1 = Sync)
    0,							// 20
    "Called Number",					// 21
    "Calling Number",					// 22
    "Sub Address",					// 23
    "Tx Connect Speed",					// 24
    "Physical Channel ID",				// 25
    "Initial Received LCP CONFREQ",			// 26
    "Last Sent LCP CONFREQ",				// 27
    "Last Received LCP CONFREQ",			// 28
    "Proxy Authen Type",				// 29
    "Proxy Authen Name",				// 30
    "Proxy Authen Challenge",				// 31
    "Proxy Authen ID",					// 32
    "Proxy Authen Response",				// 33
    "Call Errors",					// 34
    "ACCM",						// 35
    "Random Vector",					// 36
    "Private Group ID",					// 37
    "Rx Connect Speed",					// 38
    "Sequencing Required"				// 39
)

CONSTANT(l2tp_stopccn_result_code,
    0,							// 0
    "General request to clear control connection",	// 1
    "General error--Error Code indicates the problem",	// 2
    "Control channel already exists",			// 3
    "Requester is not authorized to establish a"
	" control channel",				// 4
    "The protocol version of the requester is not"
	" supported",					// 5
    "Requester is being shut down",			// 6
    "Finite State Machine error"			// 7
)

CONSTANT(l2tp_cdn_result_code,
    0,							// 0
    "Call disconnected due to loss of carrier",		// 1
    "Call disconnected for the reason indicated in"
	" error code",					// 2
    "Call disconnected for administrative reasons",	// 3
    "Call failed due to lack of appropriate facilities"
	" being available (temporary condition)",	// 4
    "Call failed due to lack of appropriate facilities"
	" being available (permanent condition)",	// 5
    "Invalid destination",				// 6
    "Call failed due to no carrier detected",		// 7
    "Call failed due to detection of a busy signal",	// 8
    "Call failed due to lack of a dial tone",		// 9
    "Call was not established within time allotted by"
	" LAC",						// 10
    "Call was connected but no appropriate framing was"
	" detected"					// 11
)

CONSTANT(l2tp_error_code,
    "No general error",					// 0
    "No control connection exists yet for this LAC-LNS"
	" pair",					// 1
    "Length is wrong",					// 2
    "One of the field values was out of range or"
	" reserved field was non-zero",			// 3
    "Insufficient resources to handle this operation"
	" now",						// 4
    "The Session ID is invalid in this context",	// 5
    "A generic vendor-specific error occurred in the"
	" LAC",						// 6
    "Try another LNS",					// 7
    "Session or tunnel was shutdown due to receipt of"
	" an unknown AVP with the M-bit set"		// 8
)

CONSTANT(ppp_phase,
    "Dead",						// 0
    "Establish",					// 1
    "Authenticate",					// 2
    "Network",						// 3
    "Terminate",					// 4
)

CONSTANT(ppp_state,
    "Initial",						// 0
    "Starting",						// 1
    "Closed",						// 2
    "Stopped",						// 3
    "Closing",						// 4
    "Stopping",						// 5
    "Request-Sent",					// 6
    "Ack-Received",					// 7
    "Ack-Sent",						// 8
    "Opened"						// 9
)

CONSTANT(ppp_auth_type,
    0,							// 0
    "Textual username/password exchange",		// 1
    "PPP CHAP",						// 2
    "PPP PAP",						// 3
    "No Authentication",				// 4
    "Microsoft CHAP Version 1 (MSCHAPv1)"		// 5
)

CONSTANT(ppp_code,
    0,							// 0
    "ConfigReq",					// 1
    "ConfigAck",					// 2
    "ConfigNak",					// 3
    "ConfigRej",					// 4
    "TerminateReq",					// 5
    "TerminateAck",					// 6
    "CodeRej",						// 7
    "ProtocolRej",					// 8
    "EchoReq",						// 9
    "EchoReply",					// 10
    "DiscardRequest",					// 11
    "IdentRequest"					// 12
)

CONSTANT(ppp_lcp_option,
    0,							// 0
    "Maximum-Receive-Unit",				// 1
    "Async-Control-Map",				// 2
    "Authentication-Protocol",				// 3
    "Quality-Protocol",					// 4
    "Magic-Number",					// 5
    0,							// 6
    "Protocol-Field-Compression",			// 7
    "Address-and-Control-Field-Compression"		// 8
)

CONSTANT(radius_state,
    "RADIUSNULL",					// 0
    "RADIUSCHAP",					// 1
    "RADIUSAUTH",					// 2
    "RADIUSSTART",					// 3
    "RADIUSSTOP",					// 4
    "RADIUSINTERIM",					// 5
    "RADIUSWAIT",					// 6
    "RADIUSJUSTAUTH"					// 7
)

CONSTANT(radius_code,
    0,							// 0
    "Access-Request",					// 1
    "Access-Accept",					// 2
    "Access-Reject",					// 3
    "Accounting-Request",				// 4
    "Accounting-Response",				// 5
    0,							// 6
    0,							// 7
    0,							// 8
    0,							// 9
    0,							// 10
    "Access-Challenge",					// 11
    "Status-Server",					// 12
    "Status-Client",					// 13
    0, 0, 0, 0, 0, 0,					// 14-19
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,			// 20-29
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,			// 30-39
    "Disconnect-Request",				// 40
    "Disconnect-ACK",					// 41
    "Disconnect-NAK",					// 42
    "CoA-Request",					// 43
    "CoA-ACK",						// 44
    "CoA-NAK"						// 45
)

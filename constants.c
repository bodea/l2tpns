#include "constants.h"
#include <memory.h>

const char *lcp_types[MAX_LCP_TYPE+1] = {
	"Reserved",
	"Maximum-Receive-Unit",
	"Async-Control-Map",
	"Authentication-Protocol",
	"Quality-Protocol",
	"Magic-Number",
	"Reserved 6",
	"Protocol-Field-Compression",
	"Address-and-Control-Field-Compression",
};

const char *avpnames[MAX_AVPNAME+1] = {
	"Message Type", // 0
	"Result Code", // 1
	"Protocol Version", // 2
	"Framing Capabilities", // 3
	"Bearer Capabilities", // 4
	"Tie Breaker", // 5
	"Firmware Revision", // 6
	"Host Name", // 7
	"Vendor Name", // 8
	"Assigned Tunnel ID", // 9
	"Receive Window Size", // 10
	"Challenge", // 11
	"Q.931 Cause Code", // 12
	"Challenge Response", // 13
	"Assigned Session ID", // 14
	"Call Serial Number", // 15
	"Minimum BPS", // 16
	"Maximum BPS", // 17
	"Bearer Type", // 18 (2 = Analog, 1 = Digital)
	"Framing Type", // 19 (2 = Async, 1 = Sync)
	"Reserved 20", // 20
	"Called Number", // 21
	"Calling Number", // 22
	"Sub Address", // 23
	"Tx Connect Speed", // 24
	"Physical Channel ID", // 25
	"Initial Received LCP CONFREQ", // 26
	"Last Sent LCP CONFREQ", // 27
	"Last Received LCP CONFREQ", // 28
	"Proxy Authen Type", // 29
	"Proxy Authen Name", // 30
	"Proxy Authen Challenge", // 31
	"Proxy Authen ID", // 32
	"Proxy Authen Response", // 33
	"Call Errors", // 34
	"ACCM", // 35
	"Random Vector", // 36
	"Private Group ID", // 37
	"Rx Connect Speed", // 38
	"Sequencing Required", // 39
};

const char *stopccn_result_codes[MAX_STOPCCN_RESULT_CODE+1] = {
	"Reserved",
	"General request to clear control connection",
	"General error--Error Code indicates the problem",
	"Control channel already exists",
	"Requester is not authorized to establish a control channel",
	"The protocol version of the requester is not supported",
	"Requester is being shut down",
	"Finite State Machine error",
};

const char *cdn_result_codes[MAX_CDN_RESULT_CODE+1] = {
	"Reserved",
	"Call disconnected due to loss of carrier",
	"Call disconnected for the reason indicated in error code",
	"Call disconnected for administrative reasons",
	"Call failed due to lack of appropriate facilities being available (temporary condition)",
	"Call failed due to lack of appropriate facilities being available (permanent condition)",
	"Invalid destination",
	"Call failed due to no carrier detected",
	"Call failed due to detection of a busy signal",
	"Call failed due to lack of a dial tone",
	"Call was not established within time allotted by LAC",
	"Call was connected but no appropriate framing was detected",
};

const char *error_codes[MAX_ERROR_CODE+1] = {
	"No general error",
	"No control connection exists yet for this LAC-LNS pair",
	"Length is wrong",
	"One of the field values was out of range or reserved field was non-zero",
	"Insufficient resources to handle this operation now",
	"The Session ID is invalid in this context",
	"A generic vendor-specific error occurred in the LAC",
	"Try another LNS",
	"Session or tunnel was shutdown due to receipt of an unknown AVP with the M-bit set",
};

const char *authtypes[MAX_AUTHTYPE+1] = {
	"Reserved",
	"Textual username/password exchange",
	"PPP CHAP",
	"PPP PAP",
	"No Authentication",
	"Microsoft CHAP Version 1 (MSCHAPv1)",
};

const char *radius_states[MAX_RADIUS_STATE+1] = {
	"RADIUSNULL",
	"RADIUSCHAP",
	"RADIUSAUTH",
	"RADIUSIPCP",
	"RADIUSSTART",
	"RADIUSSTOP",
	"RADIUSWAIT",
	NULL
};

const char *l2tp_message_types[MAX_L2TP_MESSAGE_TYPE+1] = {
	"reserved",
	"SCCRQ",
	"SCCRP",
	"SCCCN",
	"StopCCN", // 4
	"reserved",
	"HELLO",
	"OCRQ",
	"OCRP",
	"OCCN",
	"ICRQ", // 10
	"ICRP",
	"ICCN",
	"reserved",
	"CDN",
	"WEN", // 15
	"SLI",
};


// L2TPNS: control

char const *cvs_id_control = "$Id: control.c,v 1.5 2005-07-31 10:04:10 bodea Exp $";

#include <string.h>
#include "l2tpns.h"
#include "control.h"

int pack_control(uint8_t *data, int len, uint8_t type, int argc, char *argv[])
{
    struct nsctl_packet pkt;
    struct nsctl_args arg;
    char *p = pkt.argv;
    int sz = (p - (char *) &pkt);

    if (len > sizeof(pkt))
    	len = sizeof(pkt);

    if (argc > 0xff)
    	argc = 0xff; // paranoia

    pkt.magic = ntohs(NSCTL_MAGIC);
    pkt.type = type;
    pkt.argc = argc;

    while (argc-- > 0)
    {
	char *a = *argv++;
	int s = strlen(a);

	if (s > sizeof(arg.value))
		s = sizeof(arg.value); // silently truncate

	arg.len = s;
	s += sizeof(arg.len);

	if (sz + s > len)
	    return -1; // overflow

	if (arg.len)
	    memcpy(arg.value, a, arg.len);

	memcpy(p, &arg, s);
	sz += s;
	p += s;
    }

    /*
     * terminate:  this is both a sanity check and additionally
     * ensures that there's a spare byte in the packet to null
     * terminate the last argument when unpacking (see unpack_control)
     */
    if (sz + sizeof(arg.len) > len)
    	return -1; // overflow

    arg.len = 0xff;
    memcpy(p, &arg.len, sizeof(arg.len));

    sz += sizeof(arg.len);
    memcpy(data, &pkt, sz);

    return sz;
}

int unpack_control(struct nsctl *control, uint8_t *data, int len)
{
    struct nsctl_packet pkt;
    char *p = pkt.argv;
    int sz = (p - (char *) &pkt);
    int i;

    if (len < sz)
    	return NSCTL_ERR_SHORT;

    if (len > sizeof(pkt))
    	return NSCTL_ERR_LONG;

    memcpy(&pkt, data, len);
    if (ntohs(pkt.magic) != NSCTL_MAGIC)
    	return NSCTL_ERR_MAGIC;

    switch (pkt.type)
    {
    case NSCTL_REQ_LOAD:
    case NSCTL_REQ_UNLOAD:
    case NSCTL_REQ_HELP:
    case NSCTL_REQ_CONTROL:
    case NSCTL_RES_OK:
    case NSCTL_RES_ERR:
	control->type = pkt.type;
	break;

    default:
	return NSCTL_ERR_TYPE;
    }

    control->argc = pkt.argc;
    for (i = 0; i <= control->argc; i++)
    {
	unsigned s;

	if (len < sz + 1)
	    return NSCTL_ERR_SHORT;

	s = (uint8_t) *p;
	*p++ = 0; // null terminate previous arg
	sz++;

	if (i < control->argc)
	{
	    if (len < sz + s)
		return NSCTL_ERR_SHORT;

	    control->argv[i] = p;
	    p += s;
	    sz += s;
	}
	else
	{
	    /* check for terminator */
	    if (s != 0xff)
	    	return NSCTL_ERR_SHORT;
	}
    }

    if (sz != len)
    	return NSCTL_ERR_LONG; // trailing cr*p

    return control->type;
}

void dump_control(struct nsctl *control, FILE *stream)
{
    char *type = "*unknown*";

    if (!stream)
    	stream = stdout;

    switch (control->type)
    {
    case NSCTL_REQ_LOAD:	type = "NSCTL_REQ_LOAD";	break;
    case NSCTL_REQ_UNLOAD:	type = "NSCTL_REQ_UNLOAD";	break;
    case NSCTL_REQ_HELP:	type = "NSCTL_REQ_HELP";	break;
    case NSCTL_REQ_CONTROL:	type = "NSCTL_REQ_CONTROL";	break;
    case NSCTL_RES_OK:		type = "NSCTL_RES_OK";		break;
    case NSCTL_RES_ERR:		type = "NSCTL_RES_ERR";		break;
    }

    fprintf(stream, "Control packet:\n");
    fprintf(stream, "	Type: %d (%s)\n", (int) control->type, type);
    fprintf(stream, "	Args: %d", (int) control->argc);
    if (control->argc)
    {
	int i;
	fprintf(stream, " (\"");
	for (i = 0; i < control->argc; i++)
	    fprintf(stream, "%s%s", i ? "\", \"" : "", control->argv[i]);

	fprintf(stream, "\")");
    }

    fprintf(stream, "\n\n");
}

#ifndef __CONTROL_H__
#define __CONTROL_H__

#define NSCTL_PORT		1702
#define NSCTL_MAGIC		0x9013

/* builtin commands */
#define NSCTL_REQUEST		(1 << 4)
#define NSCTL_REQ_LOAD		(NSCTL_REQUEST | 1)
#define NSCTL_REQ_UNLOAD	(NSCTL_REQUEST | 2)
#define NSCTL_REQ_HELP		(NSCTL_REQUEST | 3)

/* general control message, passed to plugins */
#define NSCTL_REQ_CONTROL	(NSCTL_REQUEST | 4)

/* response messages */
#define NSCTL_RESPONSE		(1 << 5)
#define NSCTL_RES_OK		(NSCTL_RESPONSE | 1)
#define NSCTL_RES_ERR		(NSCTL_RESPONSE | 2)

/* unpack errors */
#define NSCTL_ERR_SHORT		-1	// short packet
#define NSCTL_ERR_LONG		-2	// packet exceeds max, or trailing cr*p
#define NSCTL_ERR_MAGIC		-3	// invalid magic number
#define NSCTL_ERR_TYPE		-4	// unrecognised type

#define NSCTL_MAX_PKT_SZ	4096

struct nsctl_packet {
    uint16_t magic;
    uint8_t type;
    uint8_t argc;
    char argv[NSCTL_MAX_PKT_SZ - 4];
} __attribute__ ((packed));

#define NSCTL_MAX_ARG_SZ	512

struct nsctl_args {
    uint8_t len;
    char value[NSCTL_MAX_ARG_SZ - 1];
} __attribute__ ((packed));

/* parsed packet */
struct nsctl {
    uint8_t type;
    uint8_t argc;
    char *argv[0xff];
};

int pack_control(uint8_t *data, int len, uint8_t type, int argc, char *argv[]);
int unpack_control(struct nsctl *packet, uint8_t *data, int len);
void dump_control(struct nsctl *control, FILE *stream);

#endif /* __CONTROL_H__ */

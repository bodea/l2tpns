#ifndef __TBF_H__
#define __TBF_H__

// Need a time interval.

#define TBF_MAX_QUEUE   2       // Maximum of 2 queued packet per
#define TBF_MAX_SIZE    3000    // Maxiumum queued packet size is 2048.

#define TBF_MAX_CREDIT  6000    // Maximum 6000 bytes of credit.
#define TBF_RATE        360     // 360 bytes per 1/10th of a second.

typedef struct {
        int             credit;
        int             lasttime;
        int             queued;
        int             oldest; // Position of packet in the ring buffer.
        sessionidt      sid;    // associated session ID.
        int             max_credit; // Maximum amount of credit available (burst size).
        int             rate;   // How many bytes of credit per second we get? (sustained rate)
        void            (*send)(sessionidt s, u8 *, int);       // Routine to actually send out the data.
        int             prev;   // Timer chain position.
        int             next;   // Timer chain position.

        u32     b_queued;       // Total bytes sent through this TBF
        u32     b_sent;         // Total bytes sucessfully made it to the network.
        u32     p_queued;       // ditto packets.
        u32     p_sent;         // ditto packets.
        u32     b_dropped;      // Total bytes dropped.
        u32     p_dropped;      // Total packets dropped.
        u32     p_delayed;      // Total packets not sent immediately.

        int             sizes[TBF_MAX_QUEUE];
        char            packets[TBF_MAX_QUEUE][TBF_MAX_SIZE];
} tbft;

void init_tbf(void);
int tbf_run_timer(void);
int tbf_queue_packet(int tbf_id, char * data, int size);
int new_tbf(int sid, int max_credit, int rate, void (*f)(sessionidt, u8 *, int));
int free_tbf(int tid);
void fsck_tbfs(void);

int cmd_show_tbf(struct cli_def *cli, char *command, char **argv, int argc);

#endif /* __TBF_H__ */

#ifndef __TBF_H__
#define __TBF_H__

void init_tbf(void);
int tbf_run_timer(void);
int tbf_queue_packet(int tbf_id, char * data, int size);
int new_tbf(int sid, int max_credit, int rate, void (*f)(sessionidt, u8 *, int));
int free_tbf(int tid);
void fsck_tbfs(void);

int cmd_show_tbf(struct cli_def *cli, char *command, char **argv, int argc);

#endif /* __TBF_H__ */

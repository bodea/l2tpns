// L2TPNS: token bucket filters

char const *cvs_id_tbf = "$Id: tbf.c,v 1.7 2004-10-28 03:26:41 bodea Exp $";

#define _GNU_SOURCE

#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "l2tpns.h"
#include "util.h"
#include "tbf.h"

tbft *filter_list = NULL;
static int filter_list_size = 0;

static int timer_chain = -1;	// Head of timer chain.

static void tbf_run_queue(int tbf_id);

void init_tbf(void)
{
	if (!(filter_list = shared_malloc(sizeof(*filter_list) * MAXTBFS)))
		return;

	filter_list_size = MAXTBFS;
	filter_list[0].sid = -1;	// Reserved.
}
//
// Put a TBF on the timer list.
// This is a doubly linked list..
// We put ourselves on the tail of the list.
//
static void add_to_timer(int id)
{
	if (!filter_list)
		return;

	if (timer_chain == -1) {
		filter_list[id].next = filter_list[id].prev = id;
		timer_chain = id;
		return;
	}

	filter_list[id].next = timer_chain;
	filter_list[id].prev = filter_list[timer_chain].prev;
	filter_list[filter_list[timer_chain].prev].next = id;
	filter_list[timer_chain].prev = id;
}

//
// Remove a TBF from the timer list.
// This is a doubly linked list.
static void del_from_timer(int id)
{
	if (!filter_list)
		return;

	if (filter_list[id].next == id) {	// Last element in chain?
		if (timer_chain != id) { // WTF?
			log(0,0,0,0, "Removed a singleton element from TBF, but tc didn't point to it!\n");
		} else
			timer_chain = -1;
		filter_list[id].next = filter_list[id].prev = 0;
		return;
	}

	filter_list[filter_list[id].next].prev = filter_list[id].prev;
	filter_list[filter_list[id].prev].next = filter_list[id].next;
	if (timer_chain == id)
		timer_chain = filter_list[id].next;

	filter_list[id].next = filter_list[id].prev = 0;	// Mark as off the timer chain.
}

//
// Free a token bucket filter structure for re-use.
//

int free_tbf(int tid)
{
	if (tid < 1)	// Make sure we don't free id # 0
		return -1;

	if (!filter_list)	// WTF?
		return -1;

	if (filter_list[tid].next)
		del_from_timer(tid);
	filter_list[tid].sid = 0;

	return 0;	// Done!
}

//
// Allocate a new token bucket filter.
//
int new_tbf(int sid, int max_credit, int rate, void (*f)(sessionidt, u8 *, int))
{
	int i;
	static int p = 0;

	log(3,0,0,0, "Allocating new TBF (sess %d, rate %d, helper %p)\n", sid, rate, f);

	if (!filter_list)
		return 0;	// Couldn't alloc memory!

//    again:

	for (i = 0 ; i < filter_list_size ; ++i, p = (p+1)%filter_list_size ) {
		if (filter_list[p].sid)
			continue;

		memset((void*) &filter_list[p], 0, sizeof(filter_list[p]) ); // Clear counters and data.
		filter_list[p].sid = sid;
		filter_list[p].credit = max_credit;
		filter_list[p].queued = 0;
		filter_list[p].max_credit = max_credit;
		filter_list[p].rate = rate;
		filter_list[p].oldest = 0;
		filter_list[p].send = f;
		return p;
	}

#if 0
	// All allocated filters are used! Increase the size of the allocated
	// filters.

	{
		int new_size = filter_list_size * 2;
		tbft *new = mremap(filter_list, filter_list_size * sizeof(*new), new_size * sizeof(*new), MREMAP_MAYMOVE);

		if (new == MAP_FAILED)
		{
			log(0,0,0,0, "Ran out of token bucket filters and mremap failed!  Sess %d will be un-throttled\n", sid);
			return 0;
		}

		i = filter_list_size;
		filter_list_size = new_size;
		filter_list = new;
	}

	for (; i < filter_list_size; ++i)
		filter_list[i].sid = 0;

	goto again;
#else
	log(0,0,0,0, "Ran out of token bucket filters!  Sess %d will be un-throttled\n", sid);
	return 0;
#endif
}

//
// Sanity check all the TBF records. This is
// typically done when we become a master..
//
void fsck_tbfs(void)
{
	int i , sid;

	if (!filter_list)
		return;

	for (i = 1; i < filter_list_size; ++i) {
		if (!filter_list[i].sid)	// Is it used??
			continue;

		sid = filter_list[i].sid;
		if (i != session[sid].tbf_in &&
			i != session[sid].tbf_out) { // Ooops.

			free_tbf(i);		// Mark it as free...
		}
	}

	for (i = 0; i < config->cluster_highest_sessionid ; ++i) {
		if (session[i].tbf_in && filter_list[session[i].tbf_in].sid != i) {
			filter_list[session[i].tbf_in].sid = i; // Ouch!? FIXME. What to do here?
		}
		if (session[i].tbf_out && filter_list[session[i].tbf_out].sid != i) {
			filter_list[session[i].tbf_out].sid = i; // Ouch!? FIXME. What to do here?
		}
	}
}


//
// Run a packet through a token bucket filter.
// If we can send it right away, we do. Else we
// try and queue it to send later. Else we drop it.
//
int tbf_queue_packet(int tbf_id, char * data, int size)
{
	int i;
	tbft * f;

	if (!filter_list)
		return -1;

	if (tbf_id > filter_list_size || tbf_id < 1) {	// Out of range ID??
		// Very bad. Just drop it.
		return -1;
	}

	f = &filter_list[tbf_id];

	if (!f->sid)		// Is this a real structure??
		return -1;

	tbf_run_queue(tbf_id);	// Caculate credit and send any queued packets if possible..

	f->b_queued += size;
	f->p_queued ++;

	if (!f->queued && f->credit > size) { // If the queue is empty, and we have
				// enough credit, just send it now.
		f->credit -= size;
		if (f->send) {
			f->send(f->sid, data, size);
			f->b_sent += size;
			f->p_sent ++;
		} else {
			f->b_dropped += size;
			f->p_dropped ++;
		}
		return size;
	}

		// Not enough credit. Can we have room in the queue?
	if (f->queued >= TBF_MAX_QUEUE) {
		f->p_dropped ++;
		f->b_dropped += size;
		return -1;	// No, just drop it.
	}

		// Is it too big to fit into a queue slot?
	if (size >= TBF_MAX_SIZE) {
		f->p_dropped ++;
		f->b_dropped += size;
		return -1;	// Yes, just drop it.
	}

		// Ok. We have a slot, and it's big enough to
		// contain the packet, so queue the packet!
	i = ( f->oldest + f->queued ) % TBF_MAX_QUEUE;
	memcpy(f->packets[i], data, size);

	f->sizes[i] = size;
	f->queued ++;
	f->p_delayed ++;

	if (!f->next)	// Are we off the timer chain?
		add_to_timer(tbf_id);	// Put ourselves on the timer chain.

	return 0;	// All done.
}

//
// Send queued packets from the filter if possible.
// (We're normally only called if this is possible.. )
static void tbf_run_queue(int tbf_id)
{
	tbft * f;

	if (!filter_list)
		return;

	f = &filter_list[tbf_id];

		// Calculate available credit...
	f->credit += (TIME - f->lasttime) * f->rate / 10; // current time is 1/10th of a second.
	if (f->credit > f->max_credit)
		f->credit = f->max_credit;
	f->lasttime = TIME;

	while (f->queued > 0 && f->credit >= f->sizes[f->oldest]) { // While we have enough credit..

		if (f->send) {
			f->send(f->sid, f->packets[f->oldest], f->sizes[f->oldest]);
			f->b_sent += f->sizes[f->oldest];
			f->p_sent ++;
		} else {
			f->b_dropped += f->sizes[f->oldest];
			f->p_dropped ++;
		}

		f->credit -= f->sizes[f->oldest];

		f->oldest = (f->oldest + 1 ) % TBF_MAX_QUEUE;
		f->queued--;	// One less queued packet..
	}

	if (f->queued)	// Still more to do. Hang around on the timer list.
		return;

	if (f->next)	// Are we on the timer list??
		del_from_timer(tbf_id);	// Nothing more to do. Get off the timer list.
}

//
// Periodically walk the timer list..
//
int tbf_run_timer(void)
{
	int i = timer_chain;
	int count = filter_list_size + 1;	// Safety check.
	int last = -1;
	int tbf_id; // structure being processed.

	if (timer_chain < 0)
		return 0;	// Nothing to do...

	if (!filter_list)	// No structures built yet.
		return 0;

	last = filter_list[i].prev; // last element to process.

	do {
		tbf_id = i;
		i = filter_list[i].next;	// Get the next in the queue.

		tbf_run_queue(tbf_id);	// Run the timer queue..
	} while ( timer_chain > 0 && i && tbf_id != last && --count > 0);


#if 0	// Debugging.
	for (i = 0; i < filter_list_size; ++i) {
		if (!filter_list[i].next)
			continue;
		if (filter_list[i].lasttime == TIME)	// Did we just run it?
			continue;

		log(1,0,0,0, "Missed tbf %d! Not on the timer chain?(n %d, p %d, tc %d)\n", i,
			filter_list[i].next, filter_list[i].prev, timer_chain);
		tbf_run_queue(i);
	}
#endif

	return 1;
}

int cmd_show_tbf(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	int count = 0;

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	if (!config->cluster_iam_master) {
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!filter_list)
		return CLI_OK;

	cli_print(cli,"%6s %5s %5s %6s %6s | %7s %7s %8s %8s %8s %8s", "TBF#", "Sid", "Rate", "Credit", "Queued",
		"ByteIn","PackIn","ByteSent","PackSent", "PackDrop", "PackDelay");

	for (i = 1; i < filter_list_size; ++i) {
		if (!filter_list[i].sid) // Is it used?
			continue;	// No.

		cli_print(cli, "%5d%1s %5d %5d %6d %6d | %7d %7d %8d %8d %8d %8d",
			i, (filter_list[i].next ? "*" : " "),
			filter_list[i].sid,
			filter_list[i].rate * 8,
			filter_list[i].credit,
			filter_list[i].queued,

			filter_list[i].b_queued,
			filter_list[i].p_queued,
			filter_list[i].b_sent,
			filter_list[i].p_sent,
			filter_list[i].p_dropped,
			filter_list[i].p_delayed);
		++count;
	}
	cli_print(cli, "%d tbf entries used, %d total", count, filter_list_size);
	return CLI_OK;
}

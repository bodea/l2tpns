/* kludge up some limited epoll semantics using select for 2.4 kernels */
/* $Id: fake_epoll.h,v 1.2 2007-06-28 07:22:50 bodea Exp $ */

#ifndef __FAKE_EPOLL_H__
#define __FAKE_EPOLL_H__

#define EPOLLIN		0x01
#define EPOLLOUT	0x04
#define EPOLLERR	0x08
#define EPOLLHUP	0x10

#define EPOLL_CTL_ADD	1
#define EPOLL_CTL_DEL	2
#define EPOLL_CTL_MOD	3

struct epoll_event {
    uint32_t events;
    union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
    } data;
};

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

#ifdef FAKE_EPOLL_IMPLEMENTATION

#include <sys/select.h>

static fd_set _epoll_read_set;
static fd_set _epoll_write_set;
static int _epoll_fds;
static struct epoll_event *_epoll_data[128];

static int epoll_create(int size __attribute__ ((unused)))
{
    static int once = 0;
    if (once++)
    {
	errno = ENFILE; /* only support one instance */
	return -1;
    }

    FD_ZERO(&_epoll_read_set);
    FD_ZERO(&_epoll_write_set);
    _epoll_fds = 0;

    memset(_epoll_data, 0, sizeof(_epoll_data));

    return 1; /* "descriptor" */
}

int epoll_ctl(int epfd __attribute__ ((unused)), int op, int fd,
    struct epoll_event *event)
{
    if (fd > (sizeof(_epoll_data)/sizeof(*_epoll_data)) - 1)
    {
	errno = EINVAL;
	return -1;
    }

    switch (op)
    {
    case EPOLL_CTL_ADD:
	if (event->events & EPOLLIN)
	    FD_SET(fd, &_epoll_read_set);

	if (event->events & EPOLLOUT)
	    FD_SET(fd, &_epoll_write_set);

	if (fd >= _epoll_fds)
	    _epoll_fds = fd + 1;

	if (_epoll_data[fd])
	    free(_epoll_data[fd]);

	if (!(_epoll_data[fd] = malloc(sizeof(*_epoll_data))))
	{
	    errno = ENOMEM;
	    return -1;
	}

	memcpy(_epoll_data[fd], &event->data, sizeof(*_epoll_data));
	break;

    case EPOLL_CTL_MOD:
	if (event->events & EPOLLIN)
	    FD_SET(fd, &_epoll_read_set);
	else
	    FD_CLR(fd, &_epoll_read_set);

	if (event->events & EPOLLOUT)
	    FD_SET(fd, &_epoll_write_set);
	else
	    FD_CLR(fd, &_epoll_write_set);

	memcpy(_epoll_data[fd], &event->data, sizeof(*_epoll_data));
	break;

    case EPOLL_CTL_DEL:
	FD_CLR(fd, &_epoll_read_set);
	FD_CLR(fd, &_epoll_write_set);

	free(_epoll_data[fd]);
	_epoll_data[fd] = 0;

	if (fd == _epoll_fds - 1)
	{
	    _epoll_fds = 0;
	    while (fd-- > 0)
	    {
		if (FD_ISSET(fd, &_epoll_read_set) ||
		    FD_ISSET(fd, &_epoll_write_set))
		{
		    _epoll_fds = fd + 1;
		    break;
		}
	    }
	}

	break;
    }

    return 0;
}

static int epoll_wait(int epfd __attribute__ ((unused)),
    struct epoll_event *events, int maxevents, int timout)
{
    fd_set r;
    fd_set w;
    struct timeval t;
    struct timeval *tp;
    int n;
    int e;
    int i;

    memcpy(&r, &_epoll_read_set, sizeof(r));
    memcpy(&w, &_epoll_write_set, sizeof(w));

    if (timout >= 0)
    {
	t.tv_sec = 0;
	t.tv_usec = timout * 1000;
    	tp = &t;
    }
    else
	tp = 0;

    n = select(_epoll_fds, &r, &w, 0, tp);
    if (n < 0)
    	return n;

    if (n > maxevents)
    	n = maxevents;

    for (i = e = 0; n > 0 && i < _epoll_fds; i++)
    {
	if (!_epoll_data[i])
	    continue;

	events[e].events = 0;
	if (FD_ISSET(i, &r))
	    events[e].events |= EPOLLIN;

	if (FD_ISSET(i, &w))
	    events[e].events |= EPOLLOUT;

	if (events[e].events)
	{
	    memcpy(&events[e++].data, _epoll_data[i], sizeof(events[0].data));
	    n--;
	}
    }

    return e;
}

#endif /* FAKE_EPOLL_IMPLEMENTATION */
#endif /* __FAKE_EPOLL_H__ */

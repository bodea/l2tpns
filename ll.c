// L2TPNS Linked List Stuff

char const *cvs_id_ll = "$Id: ll.c,v 1.6 2004-11-18 08:12:55 bodea Exp $";

#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "ll.h"

linked_list *ll_init()
{
	return (linked_list *)calloc(sizeof(linked_list), 1);
}

void ll_done(linked_list *l)
{
	li *i = l->head, *n;

	while (i)
	{
		n = i->next;
		free(i);
		i = n;
	}

	free(l);
}

li *ll_push(linked_list *l, void *data)
{
	li *i;

	if (!l) return NULL;
	if (!(i = (li *)calloc(sizeof(li), 1))) return NULL;

	i->data = data;
	i->next = NULL;
	if (l->end)
		l->end->next = i;
	else
		l->head = i;
	l->end = i;

	return i;
}

void *ll_pop(linked_list *l)
{
	li *i;
	void *data;

	if (!l) return NULL;
	if (!l->head)
		return NULL;

	data = l->head->data;
	i = l->head->next;
	free(l->head);
	l->head = i;
	return data;
}

void ll_iterate(linked_list *l, int(*func)(void *))
{
	li *i;
	if (!l || !func) return;

	for (i = l->head; i; i = i->next)
	{
		if (i->data && !func(i->data))
			break;
	}
}

void ll_reset(linked_list *l)
{
	if (!l) return;
	l->current = NULL;
}

void *ll_next(linked_list *l)
{
	if (!l) return NULL;
	if (!l->current)
		l->current = l->head;
	else
		l->current = l->current->next;
	if (!l->current)
		return NULL;
	return l->current->data;
}

void ll_delete(linked_list *l, void *data)
{
	li *i = l->head, *p = NULL;

	while (i)
	{
		if (i->data == data)
		{
			if (l->head == i) l->head = i->next;
			if (l->end == i)  l->end = p;
			if (p)            p->next = i->next;
			free(i);
			l->current = NULL;
			return;
		}
		p = i;
		i = i->next;
	}
}

int ll_size(linked_list *l)
{
	int count = 0;
	li *i;

	if (!l) return 0;

	for (i = l->head; i; i = i->next)
		if (i->data) count++;

	return count;
}

int ll_contains(linked_list *l, void *search)
{
	li *i;
	for (i = l->head; i; i = i->next)
		if (i->data == search)
			return 1;
	return 0;
}


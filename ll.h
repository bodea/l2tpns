#ifndef __LL_H__
#define __LL_H__

typedef struct s_li
{
    void *data;
    struct s_li *next;
} li;

typedef struct s_ll
{
    li *head;
    li *end;
    li *current;
} linked_list;

linked_list *ll_init();
void ll_done(linked_list *l);
li *ll_push(linked_list *l, void *data);
void ll_delete(linked_list *l, void *data);
void *ll_pop(linked_list *l);
void ll_iterate(linked_list *l, int(*func)(void *));
void ll_reset(linked_list *l);
void *ll_next(linked_list *l);
int ll_size(linked_list *l);
int ll_contains(linked_list *l, void *search);

#endif /* __LL_H__ */

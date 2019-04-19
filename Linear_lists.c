#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Linear_lists.h"

void string_write(char *data, Linlist_string *list)
{
    String_elem *elem = malloc(sizeof(String_elem));
    elem->data = data;
    if(list->first == list->last && list->last == NULL)
    {
        list->first = elem;
        list->last = elem;
    }
    else
    {
        elem->next = NULL;
        elem->prev = list->last;
        list->last = elem;
        elem->prev->next = elem;
    }
}

char* string_read(Linlist_string *list)
{
    char * ret = NULL;
    if(list->first)
    {
        String_elem *temp = list->first;
        list->first = list->first->next;
        ret = temp->data;
        free(temp);
    }
    return ret;
}
void int_write(const int* data, Linlist_int *list)
{
    Int_elem *elem = malloc(sizeof(Int_elem));
    elem->data = malloc(sizeof(int));
    *(elem->data) = *data;
    if(list->first == list->last && list->last == NULL)
    {
        list->first = elem;
        list->last = elem;
        elem->next = NULL;
        elem->prev = NULL;
    }
    else
    {
        elem->next = NULL;
        elem->prev = list->last;
        list->last = elem;
        elem->prev->next = elem;
    }
}
int *int_read(Linlist_int *list)
{
    int * ret = NULL;
    if(list->first)
    {
        Int_elem *temp = list->first;
        list->first = list->first->next;
        ret = temp->data;
        free(temp);
    }
    return ret;
}



void dealloc_all(Linlist_int *list) {
    if(list == NULL)
        return;
    int* num = int_read(list);
    while(num != NULL)
    {
        printf("%d\n", *num);
        num = int_read(list);
    }
    free(list);
}

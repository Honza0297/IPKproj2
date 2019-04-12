//
// Created by Honza0297 on 11.4.19.
//

#ifndef IPKPROJ2_LINEAR_LISTS_H
#define IPKPROJ2_LINEAR_LISTS_H

typedef struct string_elem{
    struct string_elem* prev;
    struct string_elem* next;
    char* data;
} String_elem;


typedef struct {
    String_elem* first;
    String_elem* last;
} Linlist_string;


typedef struct int_elem{
    struct int_elem* prev;
    struct int_elem* next;
    int* data;
} Int_elem;


typedef struct {
    Int_elem* first;
    Int_elem* last;
} Linlist_int;
void int_write(int* data, Linlist_int *list);
int *int_read(Linlist_int *list);

void string_write(char *data, Linlist_string *list);
char* string_read(Linlist_string *list);
void dealloc_all(Linlist_int *list);
#endif //IPKPROJ2_LINEAR_LISTS_H

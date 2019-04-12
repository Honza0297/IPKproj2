#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
//#include <unistd.h> //because on some platforms, getopt lives here.

#include "Linear_lists.h"
#define ERR_ARGS 1

typedef struct {
    char* udp_range;
    char* tcp_range;
    char* interface_name;
    char* domname_or_ipaddr;
} Input_args;
int err = 0;
Input_args check_args(int argc, char** argv)
{
    int opt;
    Input_args input_args = { NULL, NULL, NULL,NULL};
    while (42)
    {
        static struct option long_options[] =
                {
                        /* These options don’t set a flag.
                          We distinguish them by their indices. */
                        {"i",     required_argument, 0, 'i'},
                        {"pt",  required_argument,       0, 'u'},
                        {"pu",  required_argument, 0, 't'}
                };

        int option_index = 0;

        opt = getopt_long_only (argc, argv, "i:u:t:", long_options, &option_index);
        if(opt == -1)
            break;

        switch(opt)
        {
            case 'i':
                // printf("%c: %s\n", opt, optarg);
                input_args.interface_name = optarg;
                break;
            case 't':
                //printf("%c: %s\n", opt, optarg);
                input_args.tcp_range = optarg;
                break;
            case 'u':
                input_args.udp_range = optarg;
                //printf("%c: %s\n", opt, optarg);
                break;
            default:
                fprintf(stderr, "Error: Unknown input argument. Please check your input.\n");
        }

    }
    if(optind < argc) {
        input_args.domname_or_ipaddr = argv[optind]; //next arguments ignored
    }

    if(!(input_args.tcp_range && input_args.udp_range && input_args.domname_or_ipaddr))
    {
        fprintf(stderr, "Error: Please specify udp range, tcp range and domain name or IP address.\n");
        err = ERR_ARGS;
    }
    return input_args;
}

Linlist_int *get_TCP_range(char *str) {
    Linlist_string* temp_list = malloc(sizeof(Linlist_string));
    Linlist_int* range = malloc(sizeof(Linlist_int));
    char *splitted = strtok(str, ",");
    if(strstr(splitted, "-"))
    {
        char *start_str = strtok(splitted, "-");
        char *stop_str = strtok(NULL, "-");
        int start = strtoul(start_str, NULL, 10);
        int stop = strtoul(stop_str, NULL, 10);
        if(start > stop)
        {
            fprintf(stderr, "Error: Please specify udp range, tcp range and domain name or IP address.\n");
            err = ERR_ARGS;
        }
        for(int n = start; n < stop+1; n++)
        {
            int_write(&n,range);
        }
        free(temp_list);
        return range;
    }
    while(splitted != NULL)
    {
        string_write(splitted, temp_list);
        splitted = strtok(NULL, ",");
    }

    char* readed = string_read(temp_list);
    int converted = 0;
    while(readed != NULL)
    {
        converted = (int)strtoul(readed, NULL, 10);
        int_write(&converted, range);
        readed = string_read(temp_list);
    }
    free(temp_list);
    return range;
}

int main(int argc, char** argv ) {

    Input_args input_args = check_args(argc,argv);
    if(err)
    {
       exit(ERR_ARGS);
    }
    Linlist_int *TCP_range = get_TCP_range(input_args.tcp_range);
    Linlist_int *UDP_range = get_TCP_range(input_args.udp_range);
    if(err)
    {
        dealloc_all(TCP_range);
        dealloc_all(UDP_range);
    }
    printf("TCP:\n");
    int* num = int_read(TCP_range);
    while(num != NULL) {
        printf("%d\n", *num);
        num = int_read(TCP_range);
    }
    printf("UDP:\n");
    int* num2 = int_read(UDP_range);
    while(num2 != NULL) {
        printf("%d\n", *num2);
        num2 = int_read(UDP_range);
    }






    return 0;

}
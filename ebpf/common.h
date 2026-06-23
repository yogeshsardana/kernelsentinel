#ifndef __COMMON_H
#define __COMMON_H

#define MAX_FILENAME 256
#define MAX_COMM 16

struct event {

    __u32 pid;

    char comm[MAX_COMM];

    char filename[MAX_FILENAME];

};

#endif

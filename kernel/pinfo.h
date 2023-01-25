#ifndef XV6_PINFO_H
// #define XV6_PINFO_H

struct pinfo{
    int ppid;
    int syscall_count;
    int page_usage;
};

#endif
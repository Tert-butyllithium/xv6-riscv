#include "syscall.h"
#include "types.h"
#include "param.h"
#include "pinfo.h"
#include "riscv.h"
#include "spinlock.h"
#include "defs.h"
#include "proc.h"

extern int get_proc_cnt(void);
extern int get_syscall_cnt(void);

int sys_sysinfo(void)
{
    int param;
    argint(0, &param);
    return sysinfo(param);
}

int sysinfo(int param)
{
    switch (param)
    {
    case 0:
        return get_proc_cnt();
        break;
    case 1:
        return get_syscall_cnt();
        break;
    case 2:
        break;

    default:
        break;
    }

    return -1;
}

int sys_procinfo(void)
{
    struct pinfo pin;
    argaddr(0, (uint64 *)&pin);
    return procinfo(&pin);
}

int procinfo(struct pinfo *in)
{
    return 0;
}
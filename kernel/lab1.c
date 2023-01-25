#include "syscall.h"
#include "types.h"
#include "param.h"
#include "pinfo.h"
#include "riscv.h"
#include "spinlock.h"
#include "defs.h"
#include "proc.h"

extern int get_proc_cnt(void);
extern int free_pages_num(void);
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
        return free_pages_num();
        break;

    default:
        break;
    }

    return -1;
}

int sys_procinfo(void)
{
    // struct pinfo pin;
    uint64 pin;
    argaddr(0,&pin);
    return procinfo((struct pinfo*) pin);
}

int procinfo(struct pinfo* in)
{
    struct pinfo res;
    uint64 sz;
    struct proc *current = myproc();
    res.ppid = current->parent->pid;
    res.syscall_count = current->syscall_cnt;
    sz = current->sz;
    // res.page_usage = sz / PGSIZE;
    // if (res.page_usage * PGSIZE < sz)
    // {
    //     res.page_usage++;
    // }
    res.page_usage = PGROUNDUP(sz) >> PGSHIFT;

    // printf("ppid: %d, sysc_c: %d\n",res.ppid, res.syscall_count);

    // copy to user
    return copyout(current->pagetable, (uint64) in, (char *)&res, sizeof(struct pinfo));
}
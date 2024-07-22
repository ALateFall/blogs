---
layout: post
title: glibc2.23下的unlink源码解读
category: Heap
date: 2023-9-23 21:04:32
hide: true
---
unlink'=
<!-- more -->
[toc]
# unlink源码解读

```c
#define unlink(AV, P, BK, FD)
{
    // 将要被unlink的chunk叫做P
    FD = P->fd; // FD是P的fd
    BK = P->bk; // BK是P的bk
    // 安全检查，实际上就是P->fd->bk == P, P->bk->fd == P
    if (__builtin_expect(FD->bk != P || BK->fd != P, 0)) 
        malloc_printerr(check_action, "corrupted double-linked list", P, AV);
    else
    {
        // 通过安全检查
        // FD的bk将不再是P，而是BK
        FD->bk = BK;
        // BK的fd将不再是P，而是FD
        BK->fd = FD;
        // 不是largebin的话，unlink在这也就结束了
        
        // 假如在large bin范围内。
        // 若P不是含有fd_nextsize和bk_nextsize的那个节点，就结束了，若是还要继续往下
        if (!in_smallbin_range(P->size) && __builtin_expect(P->fd_nextsize != NULL, 0))
        {
            // largebin的额外安全检查，其实和上面类似，检查fd_nextsize和bk_nextsize
            if (__builtin_expect(P->fd_nextsize->bk_nextsize != P, 0) || __builtin_expect(P->bk_nextsize->fd_nextsize != P, 0))
                malloc_printerr(check_action, "corrupted double-linked list (not small)", P, AV);
            
            // 假如FD的fd_nextsize本来为NULL，说明FD不是该大小的第一个
            // 回想largebin的取出方式，它一定是取出该大小的第二个，也就是除了有fd_nextsize的属性的头的第一个
            if (FD->fd_nextsize == NULL)
            {
                // 那么分情况：P是不是这个largebin里面唯一一个chunk
                if (P->fd_nextsize == P)
                    // 假如是，那么BK和FD实际上largebin头
                    FD->fd_nextsize = FD->bk_nextsize = FD; 
                else
                {
                    FD->fd_nextsize = P->fd_nextsize; 
                    FD->bk_nextsize = P->bk_nextsize;
                    P->fd_nextsize->bk_nextsize = FD;
                    P->bk_nextsize->fd_nextsize = FD;
                }
            }
            else // 假如FD的fd_nextsize本来是有值的，说明它是这个大小的第一个且是唯一一个（largebin最后才取这个大小的头）
            {   //且P被unlink了，那么P这个大小也是唯一一个，那么BK也含有fd_nextsize和bk_nextsize
                // 和small bin类似
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;
            }
        }
    }
}
```


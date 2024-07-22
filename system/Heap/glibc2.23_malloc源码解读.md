---
layout: post
title: glibc2.23下的malloc源码解读
category: Heap
date: 2023-9-23 21:04:32
---
malloc
<!-- more -->
[toc]
# malloc源码解读

这里是`glibc 2.23-0ubuntu3`中的`./malloc/mallo.c`部分

```c
static void *
_int_malloc(mstate av, size_t bytes)
{
    INTERNAL_SIZE_T nb; /* normalized request size */
    unsigned int idx;   /* associated bin index */
    mbinptr bin;        /* associated bin */

    mchunkptr victim;     /* inspected/selected chunk */
    INTERNAL_SIZE_T size; /* its size */
    int victim_index;     /* its bin index */

    mchunkptr remainder;          /* remainder from a split */
    unsigned long remainder_size; /* its size */

    unsigned int block; /* bit map traverser */
    unsigned int bit;   /* bit map traverser */
    unsigned int map;   /* current word of binmap */

    mchunkptr fwd; /* misc temp for linking */
    mchunkptr bck; /* misc temp for linking */

    const char *errstr = NULL;

    /*
       Convert request size to internal form by adding SIZE_SZ bytes
       overhead plus possibly more to obtain necessary alignment and/or
       to obtain a size of at least MINSIZE, the smallest allocatable
       size. Also, checked_request2size traps (returning 0) request sizes
       that are so large that they wrap around zero when padded and
       aligned.
     */

    checked_request2size(bytes, nb); // 将用户请求的大小转化为一个系统中的大小，变量名为nb

    /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
       mmap.  */
    if (__glibc_unlikely(av == NULL)) // 大意应该是在还没有arena的时候使用mmap来分配chunk
    {
        void *p = sysmalloc(nb, av);
        if (p != NULL)
            alloc_perturb(p, bytes);
        return p;
    }

    /*
       If the size qualifies as a fastbin, first check corresponding bin.
       This code is safe to execute even if av is not yet initialized, so we
       can try it without checking, which saves some time on this fast path.
     */

    if ((unsigned long)(nb) <= (unsigned long)(get_max_fast())) // 请求的大小在fastbin之内
    {
        idx = fastbin_index(nb);             // 确定它属于10个fastbin的哪一个，获得下标
        mfastbinptr *fb = &fastbin(av, idx); // 根据下标获取这个fastbin的头
        mchunkptr pp = *fb;                  // 根据这个fastbin的头获得它的第一个chunk
        do
        {
            victim = pp;
            if (victim == NULL)
                break;
        } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd, victim)) != victim); // 遍历这个fastbin，获取对应的chunk作为victim
        if (victim != 0)                                                                         // 假如获取到了
        {
            if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) // 假如获取到的chunk的大小和请求的不同
            {
                errstr = "malloc(): memory corruption (fast)";
            errout:
                malloc_printerr(check_action, errstr, chunk2mem(victim), av);
                return NULL;
            }
            check_remalloced_chunk(av, victim, nb); // 检查是否合法
            void *p = chunk2mem(victim);            // 将chunk的系统地址转化为用户地址
            alloc_perturb(p, bytes);
            return p;
        }
    }

    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) // 请求的大小位于smallbin
    {
        idx = smallbin_index(nb); // 请求的大小属于哪一个smallbin，找到下标idx
        bin = bin_at(av, idx);    // 通过下标找到具体的这个bin

        if ((victim = last(bin)) != bin) // last宏就是#define last(b) (b->bk)，因此就是定位到smallbin的最后一个chunk，而且smallbin不为空（bin->bk!=bin）
        {
            if (victim == 0) /* initialization check */
                             // 假如smallbin为空，那么这里不会进行分配，要到后面unsortedbin。合并所有的fastbin chunk，合并到unsorted bin里面去
                malloc_consolidate(av);
            else // 定位到了这个smallbin，取出里面的一个chunk，从队尾开始取
            {
                bck = victim->bk;                        // bck是victim的bk，也就是倒数第二个
                if (__glibc_unlikely(bck->fd != victim)) // bck的fd假如不为victim说明出错
                {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                set_inuse_bit_at_offset(victim, nb); // 取出这个victim。也就是队尾的这一个。
                bin->bk = bck;                       // 取出后，bin的bk将会变成倒数第二个chunk
                bck->fd = bin;                       // 取出后，倒数第二个chunk将会指向small bin

                if (av != &main_arena) // 假如不是在主线程(main_arena)，添加上不是在main_arena的标记
                    victim->size |= NON_MAIN_ARENA;
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim); // 获得指向可用区域的指针
                alloc_perturb(p, bytes);
                return p; // 返回该指针
            }
        }
    }

    /*
       If this is a large request, consolidate fastbins before continuing.
       While it might look excessive to kill all fastbins before
       even seeing if there is space available, this avoids
       fragmentation problems normally associated with fastbins.
       Also, in practice, programs tend to have runs of either small or
       large requests, but less often mixtures, so consolidation is not
       invoked all that often in most programs. And the programs that
       it is called frequently in otherwise tend to fragment.
     */

    else // 假如该大小是属于largebin，这里是不会取出来的
    {
        idx = largebin_index(nb); // 定位到哪一个largebin
        if (have_fastchunks(av))  // 假如有fastbin chunk，统统合并到unsorted bin
            malloc_consolidate(av);
    }

    /*
       Process recently freed or remaindered chunks, taking one only if
       it is exact fit, or, if this a small request, the chunk is remainder from
       the most recent non-exact fit.  Place other traversed chunks in
       bins.  Note that this step is the only place in any routine where
       chunks are placed in bins.

       The outer loop here is needed because we might not realize until
       near the end of malloc that we should have consolidated, so must
       do so and retry. This happens at most once, and only when we would
       otherwise need to expand memory to service a "small" request.
     */

    for (;;)
    {
        int iters = 0;
        while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) // 从Unsortedbin尾部开始遍历
        {
            bck = victim->bk;                                    // 当前遍历到的chunk的bk叫做bck
            if (__builtin_expect(victim->size <= 2 * SIZE_SZ, 0) // 当前遍历到的chunk的大小不合法（小于最小值或者大于最大值），那么退出
                || __builtin_expect(victim->size > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            size = chunksize(victim); // 得到当前遍历到的chunk的大小，叫做size

            /*
               If a small request, try to use last remainder if it is the
               only chunk in unsorted bin.  This helps promote locality for
               runs of consecutive small requests. This is the only
               exception to best-fit, and applies only when there is
               no exact fit for a small chunk.
             */

            // 假如申请的chunk在smallbin范围内，且此时只有一个last_remainder在unsortedbin内部，且last_remainder还可以切割
            // 记得吗，假如small bin不为空，那么上面就已经被处理了。
            if (in_smallbin_range(nb) &&
                bck == unsorted_chunks(av) &&
                victim == av->last_remainder &&
                (unsigned long)(size) > (unsigned long)(nb + MINSIZE))
            {
                /* split and reattach remainder */
                // 将unsorted_bin里面的这个last_remainder切割后重新挂在Unsortedbin里面
                remainder_size = size - nb;                                    // 切割后的last_remainder的chunk大小
                remainder = chunk_at_offset(victim, nb);                       // 切割掉前面的部分，将切割后的指针返回
                unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder; // unsortedbin的fd和bk都指向剩余的last_remainder
                av->last_remainder = remainder;                                // 将全局变量last_remainder赋值为现在切割后的last_remainder
                remainder->bk = remainder->fd = unsorted_chunks(av);           // 同样的，last_remainder的fd和bk也指向unsorted bin
                if (!in_smallbin_range(remainder_size))                        // 若切割后的remainder已经不属于small bin的大小了，那么把fd/bk_nextsize置空
                {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                }

                // 接下来三行是将切割后的两个chunk的header标志位设置好，将切割后的last_remainder的foot设置为他现在的大小（它现在仍然为free)
                set_head(victim, nb | PREV_INUSE |
                                     (av != &main_arena ? NON_MAIN_ARENA : 0));
                set_head(remainder, remainder_size | PREV_INUSE);
                set_foot(remainder, remainder_size);

                check_malloced_chunk(av, victim, nb); // 检查一下分配出去的victim大小是否正确
                void *p = chunk2mem(victim);          // 得到用户指针
                alloc_perturb(p, bytes);
                return p;
            }

            // 假如不是只有个remainder
            // 设最后一个chunk为bck，将bck的fd指针指向unsortedbin
            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd = unsorted_chunks(av);

            /* Take now instead of binning if exact fit */

            if (size == nb) // 假如这个unsortedbin的chunk和请求的一模一样
            {
                set_inuse_bit_at_offset(victim, size); // 设置size位
                if (av != &main_arena)                 // 假如不是在main_arena还要设置对应标记
                    victim->size |= NON_MAIN_ARENA;
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p; // 返回
            }

            /* place chunk in bin */
			// 假如遍历到这个chunk并不是和用户请求的一样大，那么根据其大小放入到对应的bin里面去
            if (in_smallbin_range(size)) // 假如是small chunk。
            {
                victim_index = smallbin_index(size); // 获取small chunk对应的bin的编号
                bck = bin_at(av, victim_index);      // 将这个bin赋给bck
                fwd = bck->fd;                       // 将这个bin的fd赋给fwd，也就是这个bin的第一个chunk
                // 这里还没放回去，但是获取到了要放入的small bin的头指针和第一个chunk
            }
            else
            {
                victim_index = largebin_index(size); // 找到对应的large bin的编号
                bck = bin_at(av, victim_index);      // 将对应的large bin赋给bck
                fwd = bck->fd;                       // 将对应的large bin的fd也就是第一个chunk设置为fwd

                /* maintain large bins in sorted order */
                if (fwd != bck) // 第一个chunk不是这个bin的头指针，即不为空
                {
                    /* Or with inuse bit to speed comparisons */
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    assert((bck->bk->size & NON_MAIN_ARENA) == 0);
                    if ((unsigned long)(size) < (unsigned long)(bck->bk->size)) // bck的bk是该largebin中最小的chunk，意思就是假如比这个largebin中最小的chunk还要小
                    {
                        fwd = bck;     // fwd现在是头指针
                        bck = bck->bk; // bck现在是最小的那个chunk

                        // 下面三行会将这个chunk插入到该bin的末尾
                        victim->fd_nextsize = fwd->fd;                                    //  victim的fd_nextsize现在是第一个节点
                        victim->bk_nextsize = fwd->fd->bk_nextsize;                       // victim的bk_nextsize应该为之前第一个节点的bk_nextsize
                        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; // 同上更新指针
                    }
                    else // 假如不是比最小的chunk要小，那么要插入正确的位置
                    {
                        assert((fwd->size & NON_MAIN_ARENA) == 0);
                        while ((unsigned long)size < fwd->size) // 这个while就是通过fd_nextsize一直遍历到正确的size
                        {
                            fwd = fwd->fd_nextsize; // 更新fwd
                            assert((fwd->size & NON_MAIN_ARENA) == 0);
                        }
                        // 上面那个while存在两种遍历结果，一是遍历到了size == fwd->size，也有可能不存在和size一样大的chunk
                        // 那么这里是相等，也就是找到了
                        if ((unsigned long)size == (unsigned long)fwd->size)
                            /* Always insert in the second position.  */
                            fwd = fwd->fd; // fwd现在是这些一样大的chunk的第二个
                        else               // 假如size比fwd->size大了，那么说明没有和size一样大的chunk，victim将作为这个大小的第一个，因此会拥有fd_nextsize和bk_nextsize属性
                        {
                            victim->fd_nextsize = fwd;                 // victim的fd_nextsize指针就是fwd
                            victim->bk_nextsize = fwd->bk_nextsize;    // victim的bk_nextsize是fwd的bk_nextsize
                            fwd->bk_nextsize = victim;                 // 更新指向victim的指针
                            victim->bk_nextsize->fd_nextsize = victim; // 更新指向victim的指针
                        }
                        bck = fwd->bk;
                    }
                }
                else // 这个是if(fwd!=bck)的else，即当前largebin为空
                    // 设置victim的fd_nextsize和bk_nextsize为本身
                    victim->fd_nextsize = victim->bk_nextsize = victim;
            }

            mark_bin(av, victim_index); // 这是bitmap
            // 上面无论是插入到哪里，都没有更新fd和bk指针，这里更新这两个指针
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk = victim;
            bck->fd = victim;

#define MAX_ITERS 10000
            if (++iters >= MAX_ITERS) // 假如遍历了10000次了，那就break
                break;
        }

        /*
           If a large request, scan through the chunks of current bin in
           sorted order to find smallest that fits.  Use the skip list for this.
         */

        // 上面已经整理完了unsorted bin了
        // 若这个请求不是small bin（即就是large bin
        if (!in_smallbin_range(nb))
        {
            bin = bin_at(av, idx); // 找到对应的largebin的头指针

            /* skip scan if empty or largest chunk is too small */
            // 不为空且这个largebin中最大的chunk大于用户请求
            if ((victim = first(bin)) != bin &&
                (unsigned long)(victim->size) >= (unsigned long)(nb))
            {
                // victim现在是victim的bk_nextsize，就是该bin中大小最小的chunk
                victim = victim->bk_nextsize;
                // 遍历当前largebin，假如size小于用户请求则继续访问bk_nextsize
                while (((unsigned long)(size = chunksize(victim)) <
                        (unsigned long)(nb)))
                    victim = victim->bk_nextsize;

                /* Avoid removing the first entry for a size so that the skip
                   list does not have to be rerouted.  */
                // 假如victim不是当前largebin的最后一个chunk，且这个大小的chunk不止一个
                if (victim != last(bin) && victim->size == victim->fd->size)
                    victim = victim->fd; // 因为不止一个，所以victim就不取含有fd_nextsize指针的第一个

                // 将这个large chunk切割，剩余的部分是remainder
                remainder_size = size - nb;
                // 将这个large chunk进行unlink
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                // 假如remainder的大小比minsize还小，不管他了
                if (remainder_size < MINSIZE)
                {
                    // 设置victim的size位和mainarena位
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena)
                        victim->size |= NON_MAIN_ARENA;
                }
                /* Split */
                else // 假如remainder比minsize大，还可以用
                {
                    remainder = chunk_at_offset(victim, nb); // remainder是切割后剩下的部分
                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    // 不敢保证这个时候unsortedbin是空的，因此必须执行一次完整的插入
                    bck = unsorted_chunks(av);            // bck是unsorted bin的头指针
                    fwd = bck->fd;                        // fwd是unsortedbin的第一个chunk
                    if (__glibc_unlikely(fwd->bk != bck)) // 假如unsortedbin的第一个chunk的bk不为unsorted bin的头指针了，报错
                    {
                        errstr = "malloc(): corrupted unsorted chunks";
                        goto errout;
                    }
                    // 将remainder插入到unsortedbin中的第一个chunk
                    remainder->bk = bck;                    // remainder的bk是头指针
                    remainder->fd = fwd;                    // remainder的fd是本来的第一个chunk
                    bck->fd = remainder;                    // 头指针指向这个remainder
                    fwd->bk = remainder;                    // 原本第一个chunk的bk指向remainder
                    if (!in_smallbin_range(remainder_size)) // 假如remainder比较大，属于large chunk，还要添加指针
                    {
                        remainder->fd_nextsize = NULL; // 这两个都暂时设置为NULL
                        remainder->bk_nextsize = NULL;
                    }
                    set_head(victim, nb | PREV_INUSE |
                                         (av != &main_arena ? NON_MAIN_ARENA : 0)); // 返回给用户，设置对应的位
                    set_head(remainder, remainder_size | PREV_INUSE);
                    set_foot(remainder, remainder_size);
                }
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim); // 将chunk的地址转化为用户地址
                alloc_perturb(p, bytes);
                return p;
            }
        }

        /*
           Search for a chunk by scanning bins, starting with next largest
           bin. This search is strictly by best-fit; i.e., the smallest
           (with ties going to approximately the least recently used) chunk
           that fits is selected.

           The bitmap avoids needing to check that most blocks are nonempty.
           The particular case of skipping all bins during warm-up phases
           when no chunks have been returned yet is faster than it might look.
         */
		
        // 在这之前，我们已经找了fastbin、smallbin、unsortedbin、对应的largebin，运行到这里说明都没找到
        // 那么接下来，我们只能找一个更大的来进行切割
        // 这部分是binmap，暂时还没看明白，先跳过去看topchunk了。
        ++idx;
        bin = bin_at(av, idx); 
        block = idx2block(idx);
        map = av->binmap[block];
        bit = idx2bit(idx);

        for (;;)
        {
            /* Skip rest of block if there are no more set bits in this block.  */
            if (bit > map || bit == 0)
            {
                do
                {
                    if (++block >= BINMAPSIZE) /* out of bins */
                        goto use_top;
                } while ((map = av->binmap[block]) == 0);

                bin = bin_at(av, (block << BINMAPSHIFT));
                bit = 1;
            }

            /* Advance to bin with set bit. There must be one. */
            while ((bit & map) == 0)
            {
                bin = next_bin(bin);
                bit <<= 1;
                assert(bit != 0);
            }

            /* Inspect the bin. It is likely to be non-empty */
            victim = last(bin);

            /*  If a false alarm (empty bin), clear the bit. */
            if (victim == bin)
            {
                av->binmap[block] = map &= ~bit; /* Write through */
                bin = next_bin(bin);
                bit <<= 1;
            }

            else
            {
                size = chunksize(victim);

                /*  We know the first chunk in this bin is big enough to use. */
                assert((unsigned long)(size) >= (unsigned long)(nb));

                remainder_size = size - nb;

                /* unlink */
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                if (remainder_size < MINSIZE)
                {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena)
                        victim->size |= NON_MAIN_ARENA;
                }

                /* Split */
                else
                {
                    remainder = chunk_at_offset(victim, nb);

                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    bck = unsorted_chunks(av);
                    fwd = bck->fd;
                    if (__glibc_unlikely(fwd->bk != bck))
                    {
                        errstr = "malloc(): corrupted unsorted chunks 2";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd = remainder;
                    fwd->bk = remainder;

                    /* advertise as last remainder */
                    if (in_smallbin_range(nb))
                        av->last_remainder = remainder;
                    if (!in_smallbin_range(remainder_size))
                    {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    set_head(victim, nb | PREV_INUSE |
                                         (av != &main_arena ? NON_MAIN_ARENA : 0));
                    set_head(remainder, remainder_size | PREV_INUSE);
                    set_foot(remainder, remainder_size);
                }
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p;
            }
        }

    use_top:
        /*
           If large enough, split off the chunk bordering the end of memory
           (held in av->top). Note that this is in accord with the best-fit
           search rule.  In effect, av->top is treated as larger (and thus
           less well fitting) than any other available chunk since it can
           be extended to be as large as necessary (up to system
           limitations).

           We require that av->top always exists (i.e., has size >=
           MINSIZE) after initialization, so if it would otherwise be
           exhausted by current request, it is replenished. (The main
           reason for ensuring it exists is that we may need MINSIZE space
           to put in fenceposts in sysmalloc.)
         */
        
        // 假如别的块都不符合，那就只能top chunk来了

        victim = av->top; // victim现在是top chunk
        size = chunksize(victim); // 获取top chunk的大小

        // 分割后必须要留出一个minsize来处理请求，因此这里判断是否大于用户请求的大小+minsize
        if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) 
        {
            remainder_size = size - nb; // 切割后的部分的大小
            remainder = chunk_at_offset(victim, nb); // 获取切割后的部分的地址
            av->top = remainder; // 切割后的部分现在成为top chunk
            set_head(victim, nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0)); // 设置header位
            set_head(remainder, remainder_size | PREV_INUSE);

            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim); // 将切割出去的部分转化为用户地址
            alloc_perturb(p, bytes);
            return p;
        }

        /* When we are using atomic ops to free fast chunks we can get
           here for all block sizes.  */
        else if (have_fastchunks(av)) // 假如top chunk不满足大小要求，那么检查是不是有fastbin chunk
        {
            malloc_consolidate(av); // 有，将其全部合并
            /* restore original bin index */
            if (in_smallbin_range(nb)) // 假如nb是在small bin范围
                idx = smallbin_index(nb); // 尝试获取其idx
            else // 假如是large bin范围
                idx = largebin_index(nb); // 尝试获取其idx
        }

        /*
           Otherwise, relay to handle system-dependent cases
         */
        else
        {
            void *p = sysmalloc(nb, av);
            if (p != NULL)
                alloc_perturb(p, bytes);
            return p;
        }
    }
}
```

现在，我们来总结一下整个`glibc 2.23`的申请流程：

- 将用户请求转化为合法的真实大小

- 检查现在是不是还没有`arena`，如果没有的话，申请一块内存作为`arena`
- 检查这是不是在`fast bin`范围内，如果是的话，通过请求的大小确定它属于`fastbin`的哪一个，将其标号设为`idx`。接下来，从这个`fastbin`的头指针开始进行遍历，若找到了对应的`chunk`满足请求，那么会检查这个`chunk`所在的`fastbin`是不是刚开始的`idx`，若不是则抛出`malloc(): memory corruption(fast)`的错误，通过检查则返回给用户。
- 若不是`fast bin`范围内的，则检查是不是在`small bin`范围内。如果是的话，找到其属于的`small bin`，将其标号设为`idx`。若此时`small bin`为空，那么会调用`malloc_consolidate()`将所有的`fastbin chunk`进行合并并置入`unsorted bin`。若`small bin`不为空，那么将通过`unlink`的方式来取出`small bin`中末尾的`chunk`。
- 若不是`small bin`范围内的，那么检查是不是`large bin`范围内，若是则会合并所有的`fast bin chunk`并置入`unsorted bin`，但也仅此而已，即使在`largebin`范围内暂时也不会分配。
- 检查直接与`unsorted bin`相连的`chunk`是不是`last_remainder`，假如是，而且请求的大小又是在`small bin `范围内，因为刚刚`small bin`为空才运行到这里的，那么就尝试切割`last_remainder`，将用户请求的大小返回，切割后剩下的部分作为新的`last_remainder`。若新的`last_remainder`是在`large chunk`范围内，还要将`fd_nextsize、bk_nextsize`指针置空。
- 倒序遍历`unsorted bin`。从`unsorted bin`的最后一个`chunk`开始，假如找到一个和请求的大小一模一样的`chunk`，那么会将其返回给用户。假如不是一模一样，那么看遍历到的这个`chunk`是属于`small bin`的还是属于`large bin`的`chunk`。若其是`small bin`的`chunk`，那么将其插入到其属于的`small bin`的头部。若其是`large bin`的`chunk`，那么要根据其大小插入到正确的位置，若没有和它一样大的`chunk`还要设置`fd_nextsize`和`bk_nextsize`。遍历的时候，遍历了一万次会自动退出。
- 遍历完`unsorted bin`后，判断它是不是属于`large bin`范围内。若是，则找到其属于的`large bin`。若这个`large bin`中为空或者最大的`chunk`都不满足用户请求的大小，那么跳过这一步，看下一步。若有满足的`chunk`，那么从最小的`chunk`通过`bk_nextsize`进行遍历，找到最小的满足这个用户请求的`chunk`，若这个大小的不止一个，那么为了避免取出具有`fd_nextsize`指针的节点的`chunk`，就取出其`fd`指针指向的第二个，将其进行切割，用户请求的大小返回，剩下的部分假如还比`minsize`大则插入到`unsorted bin`中的头部，若剩下的部分仍然是属于`large chunk`的，那么会设置其`fd_nextsize`指针和`bk_nextsize`指针。
- 假如仍然没找到，此时要找到一个略大于用户请求的`chunk`来进行切割，这里是用`binmap`来进行遍历的`large bin`，此处待补充。
- 若仍然没找到，那么会去检查`top chunk`。若`top chunk`大于用户请求的`chunk`的大小再加上一个`minsize`，那么就可以对`top chunk`进行切割，将用户请求返回，剩下的部分成为新的`top chunk`。
- 若`top chunk`仍然不满足，那么检查是不是有`fast bin chunk`存在，将其全部合并。尝试获取用户请求的大小是不是在`small bin`或者`large bin`范围内。
- 还不行，只能让操作系统分配一块新的内存了。
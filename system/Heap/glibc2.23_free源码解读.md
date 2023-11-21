---
layout: post
title: glibc2.23下的free源码解读
category: system/Heap
date: 2023-9-23 21:04:32
---
free
<!-- more -->
[toc]
# free源码解读

```c
static void
_int_free(mstate av, mchunkptr p, int have_lock)
{
    INTERNAL_SIZE_T size;     /* its size */
    mfastbinptr *fb;          /* associated fastbin */
    mchunkptr nextchunk;      /* next contiguous chunk */
    INTERNAL_SIZE_T nextsize; /* its size */
    int nextinuse;            /* true if nextchunk is used */
    INTERNAL_SIZE_T prevsize; /* size of previous contiguous chunk */
    mchunkptr bck;            /* misc temp for linking */
    mchunkptr fwd;            /* misc temp for linking */

    const char *errstr = NULL;
    int locked = 0;

    // 计算要释放的chunk的大小
    size = chunksize(p);

    /* Little security check which won't hurt performance: the
       allocator never wrapps around at the end of the address space.
       Therefore we can exclude some size values which might appear
       here by accident or by "design" from some intruder.  */
    // 安全检查：指针越界或者没对齐，那么报错
    if (__builtin_expect((uintptr_t)p > (uintptr_t)-size, 0) || __builtin_expect(misaligned_chunk(p), 0))
    {
        errstr = "free(): invalid pointer";
    errout:
        if (!have_lock && locked)
            (void)mutex_unlock(&av->mutex);
        malloc_printerr(check_action, errstr, chunk2mem(p), av);
        return;
    }
    /* We know that each chunk is at least MINSIZE bytes in size or a
       multiple of MALLOC_ALIGNMENT.  */
    // 假如要释放的chunk大小甚至小于minsize或者没有对齐，那么报错
    if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size)))
    {
        errstr = "free(): invalid size";
        goto errout;
    }

    check_inuse_chunk(av, p);

    /*
      If eligible, place chunk on a fastbin so it can be found
      and used quickly in malloc.
    */
    // 假如这个chunk的大小在fastbin范围内。若设置了TRIM_FASTBINS，那么还要检查其不是直接与topchunk相连。
    if ((unsigned long)(size) <= (unsigned long)(get_max_fast())

#if TRIM_FASTBINS
        /*
    If TRIM_FASTBINS set, don't place chunks
    bordering top into fastbins
        */
        && (chunk_at_offset(p, size) != av->top)
#endif
    )
    {
        // 若要释放的chunk的下一个chunk小于Minsize，或者大于最大size，那么说明有问题，报错
        if (__builtin_expect(chunk_at_offset(p, size)->size <= 2 * SIZE_SZ, 0) || __builtin_expect(chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0))
        {
            /* We might not have a lock at this point and concurrent modifications
               of system_mem might have let to a false positive.  Redo the test
               after getting the lock.  */
            if (have_lock || ({
                    assert(locked == 0);
                    mutex_lock(&av->mutex);
                    locked = 1;
                    chunk_at_offset(p, size)->size <= 2 * SIZE_SZ || chunksize(chunk_at_offset(p, size)) >= av->system_mem;
                }))
            {
                errstr = "free(): invalid next size (fast)";
                goto errout;
            }
            if (!have_lock)
            {
                (void)mutex_unlock(&av->mutex);
                locked = 0;
            }
        }
        
        // 特定情况下初始化memory，特定情况才需要关心
        free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);

        // 计算其size属于哪一个fastbin，并获得它的头指针
        set_fastchunks(av);
        unsigned int idx = fastbin_index(size);
        fb = &fastbin(av, idx);

        /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
        // 将fastbin的第一个chunk赋值给old
        mchunkptr old = *fb, old2;
        // 将old_idx设置为最大的unsigned int值
        unsigned int old_idx = ~0u;
        do
        {
            /* Check that the top of the bin is not the record we are going to add
               (i.e., double free).  */
               // double free的一个检查，若这个fastbin里面的某个chunk就是要释放的chunk，那么报错
            if (__builtin_expect(old == p, 0))
            {
                errstr = "double free or corruption (fasttop)";
                goto errout;
            }
            /* Check that size of fastbin chunk at the top is the same as
               size of the chunk that we are adding.  We can dereference OLD
               only if we have the lock, otherwise it might have already been
               deallocated.  See use of OLD_IDX below for the actual check.  */
            // 假如要释放的chunk属于的这个fastbin不为空，那么获得这个fastbin里面的chunk属于哪一个fastbin
            if (have_lock && old != NULL)
                old_idx = fastbin_index(chunksize(old));
            p->fd = old2 = old;
        } while ((old = catomic_compare_and_exchange_val_rel(fb, p, old2)) != old2); // 假如添加成功那么循环将结束，说明只检查了与头指针相连的chunk！

        // 假如验证置入的chunk和bin里面的chunk不属于一个fastbin。报错
        if (have_lock && old != NULL && __builtin_expect(old_idx != idx, 0))
        {
            errstr = "invalid fastbin entry (free)";
            goto errout;
        }
    }

    /*
      Consolidate other non-mmapped chunks as they arrive.
    */
   // 假如不属于fastbin，且该chunk不是通过mmap映射的
    else if (!chunk_is_mmapped(p))
    {
        // 要加锁
        if (!have_lock)
        {
            (void)mutex_lock(&av->mutex);
            locked = 1;
        }
        // nextchunk变量赋值为p物理位置的下一个chunk
        nextchunk = chunk_at_offset(p, size);

        /* Lightweight tests: check whether the block is already the
           top block.  */
        // 假如要释放的chunk是top chunk，报错
        if (__glibc_unlikely(p == av->top))
        {
            errstr = "double free or corruption (top)";
            goto errout;
        }
        /* Or whether the next chunk is beyond the boundaries of the arena.  */
        // 假如内存区域不是连续的，报错。假如要释放的chunk的下一个chunk地址比top chunk还大，那么报错
        if (__builtin_expect(contiguous(av) && (char *)nextchunk >= ((char *)av->top + chunksize(av->top)), 0))
        {
            errstr = "double free or corruption (out)";
            goto errout;
        }
        /* Or whether the block is actually not marked used.  */
        // 下一个chunk有prev_inuse，假如下一个chunk说要释放的chunk p已经被释放了，那么可能double free，报错
        if (__glibc_unlikely(!prev_inuse(nextchunk)))
        {
            errstr = "double free or corruption (!prev)";
            goto errout;
        }

        // 获取下一个chunk的大小
        nextsize = chunksize(nextchunk);
        // 下一个chunk的大小不能小于最小值也不能大于最大值
        if (__builtin_expect(nextchunk->size <= 2 * SIZE_SZ, 0) || __builtin_expect(nextsize >= av->system_mem, 0))
        {
            errstr = "free(): invalid next size (normal)";
            goto errout;
        }

        free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);

        /* consolidate backward */
        // 假如要释放的chunk p的前一个chunk也是free状态，那么要发生合并。注意，fastbin不会运行到这里因此不会发生合并
        if (!prev_inuse(p))
        {
            prevsize = p->prev_size; // 通过chunk p来获得前一个chunk的大小，因此这里就可以伪造
            size += prevsize; // 获得合并后整个chunk的大小
            p = chunk_at_offset(p, -((long)prevsize)); // 将chunk p的地址设置为合并后的地址
            unlink(av, p, bck, fwd); // 将要释放的chunk p进行unlink。由于p其实是前一个chunk的地址，因此是把被合并的前一个chunk进行unlink。
        }

        // 假如chunkp的下一个chunk不是top chunk
        if (nextchunk != av->top)
        {
            /* get and clear inuse bit */
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize); // 获取chunk p的下一个chunk是否在使用，是通过下下个的prev_inuse来的

            /* consolidate forward */
            // 假如下一个chunk也是free状态，那么发生前向合并
            if (!nextinuse)
            {
                // 将下一个chunk进行unlink，
                unlink(av, nextchunk, bck, fwd);
                size += nextsize; // 前向合并简单，只需要说把p的size增大就可以了
            }
            else
                clear_inuse_bit_at_offset(nextchunk, 0); // 假如下一个chunk还在使用，由于p马上要释放了，因此把下一个chunk的prev_inuse设置为free

            /*
        Place the chunk in unsorted chunk list. Chunks are
        not placed into regular bins until after they have
        been given one chance to be used in malloc.
            */
            // 要放到unsorted bin中去了，首先将unsortedbin的头指针设置为bck
            bck = unsorted_chunks(av);
            fwd = bck->fd; // unsortedbin中第一个chunk设置为fwd
            if (__glibc_unlikely(fwd->bk != bck)) // 假如unsortedbin的第一个chunk的bk不指向unsortedbin了，出错了
            {
                errstr = "free(): corrupted unsorted chunks";
                goto errout;
            }
            // p要插入到unsortedbin的头部，也就是头指针和第一个chunk之间
            p->fd = fwd;
            p->bk = bck;
            // 假如size属于largebin，这个时候还要设置它的fd_nextsize指针和bk_nextsize指针
            if (!in_smallbin_range(size))
            {
                p->fd_nextsize = NULL;
                p->bk_nextsize = NULL;
            }
            bck->fd = p; // 头指针的fd指向p
            fwd->bk = p; // 之前的第一个chunk的bk指向p

            // 设置对应的位
            set_head(p, size | PREV_INUSE);
            set_foot(p, size);
            
            // 检查是不是真的已经释放了
            check_free_chunk(av, p);
        }

        /*
          If the chunk borders the current high end of memory,
          consolidate into top
        */

        else
        // 假如它的下一个chunk是top chunk，那么和top chunk进行合并
        {
            size += nextsize; // 加上top chunk的大小
            set_head(p, size | PREV_INUSE); // 设置标志位
            av->top = p; // 合并之后的chunk成为新的top chunk
            check_chunk(av, p); // 检查是否合法
        }

        /*
          If freeing a large space, consolidate possibly-surrounding
          chunks. Then, if the total unused topmost memory exceeds trim
          threshold, ask malloc_trim to reduce top.

          Unless max_fast is 0, we don't know if there are fastbins
          bordering top, so we cannot tell for sure whether threshold
          has been reached unless fastbins are consolidated.  But we
          don't want to consolidate on each free.  As a compromise,
          consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
          is reached.
        */
        // 假如合并之后的大小大于fastbin合并的阈值
        if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD)
        {
            // 假如有fast chunk，那么将它们合并
            if (have_fastchunks(av))
                malloc_consolidate(av);

            if (av == &main_arena)
            {
#ifndef MORECORE_CANNOT_TRIM
                if ((unsigned long)(chunksize(av->top)) >=
                    (unsigned long)(mp_.trim_threshold))
                    systrim(mp_.top_pad, av);
#endif
            }
            else
            {
                /* Always try heap_trim(), even if the top chunk is not
                   large, because the corresponding heap might go away.  */
                heap_info *heap = heap_for_ptr(top(av));

                assert(heap->ar_ptr == av);
                heap_trim(heap, mp_.top_pad);
            }
        }

        if (!have_lock)
        {
            assert(locked);
            (void)mutex_unlock(&av->mutex);
        }
    }
    /*
      If the chunk was allocated via mmap, release via munmap().
    */
   // 假如是通过mmap映射的chunk，那么应该munmap_chunk()函数将其释放
    else
    {
        munmap_chunk(p);
    }
}
```

总结一下`glibc 2.23`中的`free`的流程：

- 开始之前是一系列的安全检查，包括：
  - 要释放的地址指针是否越界，是否没对齐
  - 要释放的`chunk`大小不能小于`minsize`
- 检查其是不是属于`fastbin`范围内。若是，首先进行安全检查，检查要释放的`chunk`的下一个`chunk`大小是否小于`minsize`，或者大于`maxsize`。通过安全检查后，计算其属于哪一个`fastbin`，获得该`bin`的头指针，并以此获得与该头指针相连的`chunk`。若该`chunk`就是要释放的`chunk`，那么说明进行了`double free`，会报错。确认无误会将`chunk`加入到这个`fastbin`。若加入的`fastbin`不是最开始计算得到的`fastbin`，那么报错。
- 若其不是`fastbin`范围内，会检查是不是`mmap`映射得到的内存区域，若是，那么则交给函数`munmap_chunk()`处理。
- 若其不是`fastbin`范围内且不是`mmap`映射的内存区域，那么流程继续。先进行安全检查：
  - 要释放的`chunk`是`top chunk`，那么会报错
  - 若内存区域不再连续，报错
  - 若要释放的`chunk`的下一个`chunk`的内存地址比`top chunk`要大，那么报错
  - 检查下一个`chunk`的`prev_inuse`字段，若下一个`chunk`显示该`chunk`为`free`状态，那么报错`double free`
  - 若要释放的`chunk`的下一个`chunk`大于最大值或者小于最小值，那么报错
- 通过安全检查，若该`chunk`的前一个`chunk`处于`free`状态，那么会发生后向合并。将该`chunk`的地址加上前一个`chunk`的大小，并将前一个`chunk`进行`unlink`。注意，即使这里发生了后向合并也要继续往下运行。
- 判断要释放的`chunk`的下一个`chunk`是不是`top chunk`。若是`top chunk`，那么将会和`top chunk`发生合并：该`chunk`的大小将加上`top chunk`的大小，并且成为新的`top chunk`。
- 若不是`top chunk`，那么检查要释放的`chunk`的后一个`chunk`是不是处于`free`状态。若是，则发生前向合并，当前的`chunk`大小将会加上后一个`chunk`的大小，并且后一个`chunk`将会进行`unlink`。若后一个`chunk`不是`free`状态，那么需要把后一个`chunk`的`prev_inuse`设置为0。
- 上面的步骤已经完成了合并操作，而且其不是`fastbin`，那么我们接下来需要将其置入`unsortedbin`中。首先进行安全检查，若`unsortedbin`中的第一个`chunk`的`bk`指针没有指向`unsortedbin`，那么报错。将要释放的`chunk`插入到`unsortedbin`头指针和本来的第一个`chunk`之间即可。若其是`large chunk`，那么还需要将`fd_nextsize`指针和`bk_nextsize`指针设为`NULL`。
- 到这里`free`的过程就已经结束了。
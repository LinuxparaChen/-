# binder通信流程-servicemanager进程启动流程
1. servicemanager服务
    ```C
    int main(int argc, char **argv)
    {
        struct binder_state *bs;
        //1. 打开binder驱动，servicemanager内核空间的大小=128k
        bs = binder_open(128*1024);
        if (!bs) {
            ALOGE("failed to open binder driver\n");
            return -1;
        }
        //2. 设置成为binder的上下文管理，只能有一个。
        if (binder_become_context_manager(bs)) {
            ALOGE("cannot become context manager (%s)\n", strerror(errno));
            return -1;
        }
        ......
        //3. 循环接收binder消息，交给svcmgr_handler回调函数处理。
        binder_loop(bs, svcmgr_handler);

        return 0;
    }
    ```
2. binder_open函数
    ```C
    struct binder_state *binder_open(size_t mapsize)
    {
        struct binder_state *bs;
        struct binder_version vers;
        //申请空间。
        bs = malloc(sizeof(*bs));
        if (!bs) {
            ......//申请内存空间失败的处理。
        }
        //1. 系统的open函数会调用驱动中的binder_open函数，真正打开驱动，初始化进程。
        bs->fd = open("/dev/binder", O_RDWR);
        if (bs->fd < 0) {
            ......//打开binder驱动失败的处理。
        }
        //2. 调用系统的ioctl函数发送命令，会调用binder驱动的binder_ioctl函数，BINDER_VERSION：获取binder驱动的版本号。
        //binder 驱动收到命令，直接将版本号放入到vers->protocol_version中，使用put_user函数。
        if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
            (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
            ......//获取binder版本号失败的处理。
        }

        bs->mapsize = mapsize;
        //3. 调用系统的mmap函数映射虚拟内存，会调用binder驱动的binder_mmap函数。在内核中开辟空间。
        //参数1：起始位置
        //参数2：长度
        //参数3：PROT_READ=页面内容可以被读取
        //参数4：MAP_PRIVATE=私有映射，内存区域的写入不会影响到原文件。
        //参数5：文件描述符（由open函数返回）
        //参数6：表示被映射对象（即文件）从那里开始对映，通常都是用0。
        bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
        if (bs->mapped == MAP_FAILED) {
            ......//映射虚拟内存失败的处理
        }

        return bs;
    ......
    }
    ```

3. binder_become_context_manager函数
    ```C
    int binder_become_context_manager(struct binder_state *bs)
    {
        //发送BINDER_SET_CONTEXT_MGR命令到binder驱动
        return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
    }
    ```

4. binder_loop函数

    ```C
    void binder_loop(struct binder_state *bs, binder_handler func)
    {
        int res;
        //读写数据的结构体
        struct binder_write_read bwr;
        uint32_t readbuf[32];

        bwr.write_size = 0;
        bwr.write_consumed = 0;
        bwr.write_buffer = 0;

        readbuf[0] = BC_ENTER_LOOPER;
        //调用ioctl发送给binder命令(BINDER_WRITE_READ)，携带的数据(BC_ENTER_LOOPER)。
        //参见：binder.c(驱动)中的binder_thread_write函数，命令=BC_ENTER_LOOPER。
        binder_write(bs, readbuf, sizeof(uint32_t));

        for (;;) {
            bwr.read_size = sizeof(readbuf);
            bwr.read_consumed = 0;
            bwr.read_buffer = (uintptr_t) readbuf;

            //读取binder驱动中的数据。此时没有数据可读取，while(1)循环跳出。返回0。
            //参见：binder.c(驱动)中的binder_thread_read函数。
            res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

            if (res < 0) {
                ......//错误处理
            }

            //ioctl暂时没有读取到任何数据
            res = binder_parse(bs, 0, (uintptr_t) readbuf, bwr.read_consumed, func);
            if (res == 0) {
                ALOGE("binder_loop: unexpected reply?!\n");
                break;
            }
            if (res < 0) {
                ALOGE("binder_loop: io error %d %s\n", res, strerror(errno));
                break;
            }
        }
    }
    ```

---
#### 以下分析是binder驱动层代码(binder_ioctl函数)，servicemanager服务循环时执行的流程。

1. binder_write函数(servicemanager进程)
    ```C
    int binder_write(struct binder_state *bs, void *data, size_t len)
    {
        struct binder_write_read bwr;
        int res;

        bwr.write_size = len;
        bwr.write_consumed = 0;
        //data = [BC_ENTER_LOOP,0,0,0,0,0,......]32个元素的数组。
        bwr.write_buffer = (uintptr_t) data;
        bwr.read_size = 0;
        bwr.read_consumed = 0;
        bwr.read_buffer = 0;
        //调用驱动层binder_ioctl函数，传入命令BINDER_WRITE_READ
        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
        if (res < 0) {
            fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                    strerror(errno));
        }
        return res;
    }
    ```

2. binder_ioctl函数
    ```C
    static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
    {
    	int ret;
    	//servicemanager进程
    	struct binder_proc *proc = filp->private_data;
    	struct binder_thread *thread;
    	unsigned int size = _IOC_SIZE(cmd);//cmd = BINDER_WRITE_READ
    	void __user *ubuf = (void __user *)arg;//[BC_ENTER_LOOP,0,0,0,0,0,......]32个元素的数组。

        ......
    	//进程进入休眠，binder_stop_on_user_error < 2条件满足唤醒进程，binder_stop_on_user_error默认=0，条件满足。
    	//返回0。
    	ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    	if (ret)
    		goto err_unlocked;

    	binder_lock(__func__);
    	thread = binder_get_thread(proc);
    	if (thread == NULL) {
    		......//错误处理
    	}

    	switch (cmd) {
    	case BINDER_WRITE_READ:
    		//见：3.
    		ret = binder_ioctl_write_read(filp, cmd, arg, thread);
    		if (ret)
    			goto err;
    		break;
    	case BINDER_SET_MAX_THREADS:
    		......
    		break;
    	case BINDER_SET_CONTEXT_MGR:
    		......
    		break;
    	case BINDER_THREAD_EXIT:
    		......
    		break;
    	case BINDER_VERSION: {
    		.....
    		break;
    	}
    	default:
    		......//错误处理
    	}
    	ret = 0;
    err:
    	//设置线程状态，需要返回。
    	if (thread)
    		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
    	binder_unlock(__func__);
    	//同上
    	wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    	......
    err_unlocked:
    	trace_binder_ioctl_done(ret);
    	return ret;
    }
    ```

3. binder_ioctl_write_read函数。
    ```C
    static int binder_ioctl_write_read(struct file *filp,
    				unsigned int cmd, unsigned long arg,
    				struct binder_thread *thread)
    {
    	int ret = 0;
    	struct binder_proc *proc = filp->private_data;
    	unsigned int size = _IOC_SIZE(cmd);
    	void __user *ubuf = (void __user *)arg;
    	struct binder_write_read bwr;

    	if (size != sizeof(struct binder_write_read)) {
    		......//错误处理
    	}
    	//copy_from_user成功返回0，从用户空间拷贝到内核空间。
    	if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
    		......//错误处理
    	}
    	......

    	if (bwr.write_size > 0) {
    		//servicemanager进程中binder_write函数会执行此分支，bwr.write_size = len,bwr.read_size = 0.
    		//见：4.
    		ret = binder_thread_write(proc, thread,
    					  bwr.write_buffer,
    					  bwr.write_size,
    					  &bwr.write_consumed);

    		if (ret < 0) {
    			......//错误处理
    		}
    	}
    	if (bwr.read_size > 0) {
    	    //servicemanager进程中for(;;)循环中的ioctl会执行此分支。
    	    //bwr.read_size   是readbuf数组的大小 = 32*4 = 128
    	    //bwr.read_buffer 是readbuf数组
    	    //bwr.read_consumed 值 = 0。write相关的都为NULL或者0
    	    //见：5.
    		ret = binder_thread_read(proc, thread, bwr.read_buffer,
    					 bwr.read_size,
    					 &bwr.read_consumed,
    					 filp->f_flags & O_NONBLOCK);

    		if (!list_empty(&proc->todo))
    			wake_up_interruptible(&proc->wait);
    		if (ret < 0) {
    			......//错误处理
    		}
    	}
    	......
    	//BC_ENTER_LOOP执行完成后，数据没有变化，拷贝回用户空间并释放。
    	//for(;;)读取数据时
    	if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
    		......//错误处理
    	}
    out:
    	return ret;
    }
    ```

4. binder_thread_write函数
    ```C
    static int binder_thread_write(struct binder_proc *proc,
    			struct binder_thread *thread,
    			binder_uintptr_t binder_buffer, size_t size,
    			binder_size_t *consumed)
    {
    	uint32_t cmd;
    	void __user *buffer = (void __user *)(uintptr_t)binder_buffer;//[BC_ENTER_LOOP,0,0,0,0,0,......]
    	void __user *ptr = buffer + *consumed;//*consumed=0
    	void __user *end = buffer + size;//size = 4

    	while (ptr < end && thread->return_error == BR_OK) {
    		//从用户空间拷贝到内核空间 cmd = BC_ENTER_LOOP
    		if (get_user(cmd, (uint32_t __user *)ptr))
    			return -EFAULT;
    		ptr += sizeof(uint32_t);

    		......
    		switch (cmd) {
    		......
    		case BC_ENTER_LOOPER:
    			......
    			thread->looper |= BINDER_LOOPER_STATE_ENTERED;
    			break;
    		......

    		default:
    			pr_err("%d:%d unknown command %d\n",
    			       proc->pid, thread->pid, cmd);
    			return -EINVAL;
    		}
    		*consumed = ptr - buffer;
    	}
    	return 0;
    }
    ```

5. binder_thread_read函数
    ```C
    static int binder_thread_read(struct binder_proc *proc,
    			      struct binder_thread *thread,
    			      binder_uintptr_t binder_buffer, size_t size,
    			      binder_size_t *consumed, int non_block)
    {
    	//[BC_ENTER_LOOP,0,0,0,0,0,......]
    	void __user *buffer = (void __user *)(uintptr_t)binder_buffer;
    	void __user *ptr = buffer + *consumed;//*consumed = 0
    	void __user *end = buffer + size;//size = 128

    	int ret = 0;
    	int wait_for_proc_work;

    	if (*consumed == 0) {
    		//用户空间的数据修改成[BR_NOOP,0,0,0,0,0,......]，内核空间数据不变
    		if (put_user(BR_NOOP, (uint32_t __user *)ptr))
    			return -EFAULT;
    		ptr += sizeof(uint32_t);//指针后移一个元素。
    	}

    retry:
        //thread->transaction_stack 默认 = null，thread赋值在binder_get_thread函数中。
    	//wait_for_proc_work = true;
    	wait_for_proc_work = thread->transaction_stack == NULL &&
    				list_empty(&thread->todo);

    	//thread->return_error 默认=BR_OK。
    	if (thread->return_error != BR_OK && ptr < end) {
    		......//
    	}

    	//修改线程状态
    	thread->looper |= BINDER_LOOPER_STATE_WAITING;
    	if (wait_for_proc_work)
    		proc->ready_threads++;

    	binder_unlock(__func__);

    	......
    	if (wait_for_proc_work) {//for(;;)循环执行此分支。
    		......//省略的代码不执行
    		binder_set_nice(proc->default_priority);
    		if (non_block) {//false
    			......
    		} else
    			//休眠等待任务。
    			ret = wait_event_freezable_exclusive(thread->wait, binder_has_thread_work(proc,thread));
    	} else {
    		......
    	}

    	......
    }
    ```
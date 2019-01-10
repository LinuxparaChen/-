# binder驱动笔记

1. 初始化驱动。
    ```C
    //当系统加载驱动的时候，会调用binder_init函数。
    device_initcall(binder_init);

    1.1 binder_init函数
    static int __init binder_init(void)
    {
    	int ret;

    	//创建binder的工作队列。
    	binder_deferred_workqueue = create_singlethread_workqueue("binder");
    	if (!binder_deferred_workqueue)
    		return -ENOMEM;
    	......
    	//注册设备。
    	ret = misc_register(&binder_miscdev);
    	......
    	return ret;
    }

    1.2 binder_miscdev结构体
    static struct miscdevice binder_miscdev = {
    	.minor = MISC_DYNAMIC_MINOR,//驱动的次设备号 misc设备的主设备好永远都是10。
    	.name = "binder",//驱动名称
    	.fops = &binder_fops//binder驱动文件的操作函数结构体。
    };

    1.3 file_operations结构体。
    static const struct file_operations binder_fops = {
    	.owner = THIS_MODULE,//拥有者，一般都是THIS_MODULE。
    	//poll 驱动提供给应用程序探测设备文件是否有数据可读
    	.poll = binder_poll,//系统poll,epoll,select都是探测函数，探测数据是否可读的时候将会调用 binder_poll函数。
    	//调用系统函数ioctl时调用。
    	.unlocked_ioctl = binder_ioctl,//应用程序，向驱动发送命令时，调用的函数。2.6.36后的kernel删除了ioctl。
    	.compat_ioctl = binder_ioctl,//同上，32位程序，调用64位kernel时调用。
    	.mmap = binder_mmap,//调用系统函数mmap时调用，用于映射虚拟内存空间。
    	.open = binder_open,//调用系统函数open("/dev/binder")时调用。
    	.flush = binder_flush,//系统函数flush，暂时忽略
    	.release = binder_release,//系统函数release，暂时忽略
    };
    ```

2. binder_open函数
    ```C
    static int binder_open(struct inode *nodp, struct file *filp)
    {
    	struct binder_proc *proc;
    	//内核中申请空间
    	proc = kzalloc(sizeof(*proc), GFP_KERNEL);
    	if (proc == NULL)
    		return -ENOMEM;
    	proc->tsk = current;
    	//初始化进程的<待办列表>。
    	INIT_LIST_HEAD(&proc->todo);
    	//初始化进程的<等待队列>。
    	init_waitqueue_head(&proc->wait);
    	proc->default_priority = task_nice(current);

    	binder_lock(__func__);

    	//修改binder的状态
    	binder_stats_created(BINDER_STAT_PROC);
    	//添加进程，到binder_procs队列中。
    	hlist_add_head(&proc->proc_node, &binder_procs);
    	proc->pid = current->group_leader->pid;
    	INIT_LIST_HEAD(&proc->delivered_death);
    	filp->private_data = proc;

    	binder_unlock(__func__);
    	......
    	return 0;
    }
    ```

3. binder_ioctl函数
    ```C
    static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
    {
    	int ret;
    	//打开驱动的进程。
    	struct binder_proc *proc = filp->private_data;
    	struct binder_thread *thread;
    	unsigned int size = _IOC_SIZE(cmd);
    	void __user *ubuf = (void __user *)arg;

    	//挂起进程，等待 binder_stop_on_user_error < 2 条件满足，条件满足返回0。binder_stop_on_user_error默认=0，条件满足。
    	ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    	if (ret)
    		goto err_unlocked;

    	binder_lock(__func__);
    	//创建一个binder_thread，
    	//return_error = BR_OK
    	thread = binder_get_thread(proc);
    	if (thread == NULL) {
    		......//创建binder线程失败的处理。
    	}

    	switch (cmd) {
    	//binder 读写数据
    	case BINDER_WRITE_READ:
    		ret = binder_ioctl_write_read(filp, cmd, arg, thread);
    		if (ret)
    			goto err;
    		break;
    	//设置一个进程可创建的binder线程的最大线程数。
    	case BINDER_SET_MAX_THREADS:
    		if (copy_from_user(&proc->max_threads, ubuf, sizeof(proc->max_threads))) {
    			ret = -EINVAL;
    			goto err;
    		}
    		break;
    	//设置成为binder的上下文管理。
    	case BINDER_SET_CONTEXT_MGR:
    		ret = binder_ioctl_set_ctx_mgr(filp);
    		if (ret)
    			goto err;
    		ret = security_binder_set_context_mgr(proc->tsk);
    		if (ret < 0)
    			goto err;
    		break;
    	//binder 线程退出
    	case BINDER_THREAD_EXIT:
    		binder_debug(BINDER_DEBUG_THREADS, "%d:%d exit\n",
    			     proc->pid, thread->pid);
    		binder_free_thread(proc, thread);
    		thread = NULL;
    		break;
    	//获取binder 版本号
    	case BINDER_VERSION: {
    		//protocol_version 32位整数
    		struct binder_version __user *ver = ubuf;

    		if (size != sizeof(struct binder_version)) {
    			......
    		}
    		//将BINDER_CURRENT_PROTOCOL_VERSION 32位=7 剩下的=8放入到用户空间 ver=ubuf=arg。
    		if (put_user(BINDER_CURRENT_PROTOCOL_VERSION,
    			     &ver->protocol_version)) {
    			......//失败的处理
    		}
    		break;
    	}
    	default:
    		......//不识别的命令，走失败。
    	}
    	ret = 0;
    	......//失败处理。返回负数。
    	return ret;
    }
    ```

4. binder_mmap函数
    ```C
    static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
    {
    	int ret;
    	struct vm_struct *area;
    	struct binder_proc *proc = filp->private_data;
    	const char *failure_string;
    	struct binder_buffer *buffer;

    	if (proc->tsk != current)
    		return -EINVAL;

    	//限制映射内存的大小。
    	if ((vma->vm_end - vma->vm_start) > SZ_4M)
    		vma->vm_end = vma->vm_start + SZ_4M;
    	......
    	vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE;

    	mutex_lock(&binder_mmap_lock);
    	if (proc->buffer) {
    		......//该线程已经映射过内存了。跳到错误处理。
    	}

    	//申请虚拟空间
    	area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP);
    	if (area == NULL) {
    		......//获取虚拟区域失败，跳到错误处理。
    	}
    	proc->buffer = area->addr;
    	proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;
    	mutex_unlock(&binder_mmap_lock);

    	//申请内核空间。
    	proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) / PAGE_SIZE), GFP_KERNEL);
    	if (proc->pages == NULL) {
    		......//申请失败，跳到错误处理。
    	}
    	proc->buffer_size = vma->vm_end - vma->vm_start;

    	vma->vm_ops = &binder_vm_ops;
    	vma->vm_private_data = proc;

    	//关联虚拟空间和内核空间。
    	if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) {
    		ret = -ENOMEM;
    		failure_string = "alloc small buf";
    		goto err_alloc_small_buf_failed;
    	}
    	buffer = proc->buffer;
    	INIT_LIST_HEAD(&proc->buffers);
    	list_add(&buffer->entry, &proc->buffers);
    	buffer->free = 1;
    	binder_insert_free_buffer(proc, buffer);
    	proc->free_async_space = proc->buffer_size / 2;
    	barrier();
    	proc->files = get_files_struct(current);
    	proc->vma = vma;
    	proc->vma_vm_mm = vma->vm_mm;

    	return 0;

    ......//错误处理，返回负数。
    }

    ```
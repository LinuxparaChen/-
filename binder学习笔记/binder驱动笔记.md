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

    	if (binder_debugfs_dir_entry_proc) {
    		char strbuf[11];

    		snprintf(strbuf, sizeof(strbuf), "%u", proc->pid);
    		proc->debugfs_entry = debugfs_create_file(strbuf, S_IRUGO,
    			binder_debugfs_dir_entry_proc, proc, &binder_proc_fops);
    	}

    	return 0;
    }
    ```
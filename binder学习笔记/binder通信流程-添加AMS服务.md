# binder通信流程-添加AMS服务
启动AMS服务前，相关的系统启动流程不在本页面中，具体系统启动流程请参见：
1. ServiceManager.addService函数
    ```java
    public static void addService(String name, IBinder service) {
        try {
            getIServiceManager().addService(name, service, false);
        } catch (RemoteException e) {
            Log.e(TAG, "error in addService", e);
        }
    }

    private static IServiceManager getIServiceManager() {
        if (sServiceManager != null) {
            return sServiceManager;
        }

        // Find the service manager
        sServiceManager = ServiceManagerNative.asInterface(BinderInternal.getContextObject());
        return sServiceManager;
    }
    ```

2. BinderInternal.getContextObject()函数
    ```java
    //调用本地函数，获取servicemanager。本地方法在android_util_Binder.cpp中。
    public static final native IBinder getContextObject();
    ```
    ```c
    //动态注册
    static const JNINativeMethod gBinderInternalMethods[] = {
         /* name, signature, funcPtr */
        { "getContextObject", "()Landroid/os/IBinder;", (void*)android_os_BinderInternal_getContextObject },
        { "joinThreadPool", "()V", (void*)android_os_BinderInternal_joinThreadPool },
        { "disableBackgroundScheduling", "(Z)V", (void*)android_os_BinderInternal_disableBackgroundScheduling },
        { "handleGc", "()V", (void*)android_os_BinderInternal_handleGc }
    };

    static jobject android_os_BinderInternal_getContextObject(JNIEnv* env, jobject clazz)
    {
        //获取servicemanager对象。
        sp<IBinder> b = ProcessState::self()->getContextObject(NULL);
        //转成javaBinder对象。
        return javaObjectForIBinder(env, b);
    }
    ```

3. ProcessState::self()->getContextObject(NULL)函数
    ```c
    //单例，一个进程只会获取一个ProcessState对象。
    sp<ProcessState> ProcessState::self()
    {
        Mutex::Autolock _l(gProcessMutex);
        if (gProcess != NULL) {
            return gProcess;
        }
        gProcess = new ProcessState;
        return gProcess;
    }

    sp<IBinder> ProcessState::getContextObject(const sp<IBinder>& /*caller*/)
    {
        //获取servicemanager(0)代理对象。
        return getStrongProxyForHandle(0);
    }

    sp<IBinder> ProcessState::getStrongProxyForHandle(int32_t handle)
    {
        sp<IBinder> result;

        AutoMutex _l(mLock);
        //根据handle查找对应的handle_entry，找不到时会创建一个对象，但内容为null。
        handle_entry* e = lookupHandleLocked(handle);

        if (e != NULL) {

            IBinder* b = e->binder;
            if (b == NULL || !e->refs->attemptIncWeak(this)) {
                if (handle == 0) {
                    //如果handle是servicemanager的handle需要ping命令确认存活。
                    Parcel data;
                    status_t status = IPCThreadState::self()->transact(
                            0, IBinder::PING_TRANSACTION, data, NULL, 0);
                    if (status == DEAD_OBJECT)
                       return NULL;
                }
                //创建binder的的代理对象。
                b = new BpBinder(handle);
                e->binder = b;
                if (b) e->refs = b->getWeakRefs();
                result = b;
            } else {
                e->refs->decWeak(this);
            }
        }

        return result;
    }
    ```

4. IPCThreadState::self()->transact函数
    ```c
    //确保一个线程，只有一个IPCThreadState对象。
    IPCThreadState* IPCThreadState::self()
    {
        if (gHaveTLS) {
    restart:
            const pthread_key_t k = gTLS;
            IPCThreadState* st = (IPCThreadState*)pthread_getspecific(k);
            if (st) return st;
            return new IPCThreadState;
        }

        if (gShutdown) return NULL;

        pthread_mutex_lock(&gTLSMutex);
        if (!gHaveTLS) {
            if (pthread_key_create(&gTLS, threadDestructor) != 0) {
                pthread_mutex_unlock(&gTLSMutex);
                return NULL;
            }
            gHaveTLS = true;
        }
        pthread_mutex_unlock(&gTLSMutex);
        goto restart;
    }

    //向binder驱动传输数据
    status_t IPCThreadState::transact(int32_t handle,
                                      uint32_t code, const Parcel& data,
                                      Parcel* reply, uint32_t flags)//flags = 0 reply = null
    {
        //Parcel的errorCheck默认=NO_ERROR
        status_t err = data.errorCheck();

        flags |= TF_ACCEPT_FDS;

        if (err == NO_ERROR) {
            //写入传输数据，使用BC_TRANSACTION命令码包装PING_TRANSACTION命令码
            //flags = 0
            //handle = 0
            //code = PING_TRANSACTION
            //data = 无数据，但是对象不为空
            //此函数的作用重新包装数据，命令BC_TRANSACTION，binder_transact_data,写入到mOut(Parcel)中。
            err = writeTransactionData(BC_TRANSACTION, flags, handle, code, data, NULL);
        }

        ......

        if ((flags & TF_ONE_WAY) == 0) {//条件成立0&任何数=0
            ......
            if (reply) {
                err = waitForResponse(reply);
            } else {
                //执行此分支
                Parcel fakeReply;
                err = waitForResponse(&fakeReply);
            }
            ......
        } else {
            err = waitForResponse(NULL, NULL);
        }

        return err;
    }
    ```

5. IPCThreadState::waitForResponse函数
    ```c
    status_t IPCThreadState::waitForResponse(Parcel *reply, status_t *acquireResult)
    {
        uint32_t cmd;
        int32_t err;

        while (1) {
            //重要，真正和驱动传输数据。
            if ((err=talkWithDriver()) < NO_ERROR) break;
            err = mIn.errorCheck();
            if (err < NO_ERROR) break;
            if (mIn.dataAvail() == 0) continue;

            cmd = (uint32_t)mIn.readInt32();

            IF_LOG_COMMANDS() {
                alog << "Processing waitForResponse Command: "
                    << getReturnString(cmd) << endl;
            }

            switch (cmd) {
            case BR_TRANSACTION_COMPLETE:
                if (!reply && !acquireResult) goto finish;
                break;

            case BR_DEAD_REPLY:
                err = DEAD_OBJECT;
                goto finish;

            case BR_FAILED_REPLY:
                err = FAILED_TRANSACTION;
                goto finish;

            case BR_ACQUIRE_RESULT:
                {
                    ALOG_ASSERT(acquireResult != NULL, "Unexpected brACQUIRE_RESULT");
                    const int32_t result = mIn.readInt32();
                    if (!acquireResult) continue;
                    *acquireResult = result ? NO_ERROR : INVALID_OPERATION;
                }
                goto finish;

            case BR_REPLY:
                {
                    binder_transaction_data tr;
                    err = mIn.read(&tr, sizeof(tr));
                    ALOG_ASSERT(err == NO_ERROR, "Not enough command data for brREPLY");
                    if (err != NO_ERROR) goto finish;

                    if (reply) {
                        if ((tr.flags & TF_STATUS_CODE) == 0) {
                            reply->ipcSetDataReference(
                                reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                                tr.data_size,
                                reinterpret_cast<const binder_size_t*>(tr.data.ptr.offsets),
                                tr.offsets_size/sizeof(binder_size_t),
                                freeBuffer, this);
                        } else {
                            err = *reinterpret_cast<const status_t*>(tr.data.ptr.buffer);
                            freeBuffer(NULL,
                                reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                                tr.data_size,
                                reinterpret_cast<const binder_size_t*>(tr.data.ptr.offsets),
                                tr.offsets_size/sizeof(binder_size_t), this);
                        }
                    } else {
                        freeBuffer(NULL,
                            reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                            tr.data_size,
                            reinterpret_cast<const binder_size_t*>(tr.data.ptr.offsets),
                            tr.offsets_size/sizeof(binder_size_t), this);
                        continue;
                    }
                }
                goto finish;

            default:
                err = executeCommand(cmd);
                if (err != NO_ERROR) goto finish;
                break;
            }
        }
    ```

6. IPCThreadState::talkWithDriver函数
    ```c
    status_t IPCThreadState::talkWithDriver(bool doReceive)//doReceive = 0 = false
    {
        ......

        binder_write_read bwr;

        const bool needRead = mIn.dataPosition() >= mIn.dataSize();

        //三目运算符返回mOut.dataSize > 0
        const size_t outAvail = (!doReceive || needRead) ? mOut.dataSize() : 0;

        bwr.write_size = outAvail;
        bwr.write_buffer = (uintptr_t)mOut.data();

        // This is what we'll read.
        if (doReceive && needRead) {
            bwr.read_size = mIn.dataCapacity();
            bwr.read_buffer = (uintptr_t)mIn.data();
        } else {
            //执行此分支
            bwr.read_size = 0;
            bwr.read_buffer = 0;
        }
        //条件=false
        if ((bwr.write_size == 0) && (bwr.read_size == 0)) return NO_ERROR;

        bwr.write_consumed = 0;
        bwr.read_consumed = 0;
        status_t err;
        do {
            ......
            //发送binder驱动命令
            if (ioctl(mProcess->mDriverFD, BINDER_WRITE_READ, &bwr) >= 0)
                err = NO_ERROR;
            else
                err = -errno;

            ......
        } while (err == -EINTR);

        if (err >= NO_ERROR) {
            if (bwr.write_consumed > 0) {
                if (bwr.write_consumed < mOut.dataSize())
                    mOut.remove(0, bwr.write_consumed);
                else
                    mOut.setDataSize(0);
            }
            if (bwr.read_consumed > 0) {
                mIn.setDataSize(bwr.read_consumed);
                mIn.setDataPosition(0);
            }

            return NO_ERROR;
        }

        return err;
    }
    ```

---
以下为binder驱动代码
1. binder_ioctl函数
    ```c
    static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
    {
    	int ret;
    	//AMS进程
    	struct binder_proc *proc = filp->private_data;
    	struct binder_thread *thread;
    	unsigned int size = _IOC_SIZE(cmd);//cmd = BINDER_WRITE_READ
    	void __user *ubuf = (void __user *)arg;

    	ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    	if (ret)
    		goto err_unlocked;

    	binder_lock(__func__);
    	thread = binder_get_thread(proc);
    	if (thread == NULL) {
    		......
    	}

    	switch (cmd) {
    	case BINDER_WRITE_READ:
    		ret = binder_ioctl_write_read(filp, cmd, arg, thread);
    		if (ret)
    			goto err;
    		break;
    	......
    	default:
    		......//不识别的命令处理
    	}
    	ret = 0;
    err:
    	if (thread)
    		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
    	binder_unlock(__func__);
    	wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
    	......
    	return ret;
    }

    ```

2. binder_ioctl_write_read函数
    ```c
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
    	//从用户空间，拷贝到内核空间，ubuf包含BC_TRANSACT、PING_TRANSACTION
    	if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
    		......//错误处理
    	}
    	......

    	if (bwr.write_size > 0) {
    		ret = binder_thread_write(proc, thread,
    					  bwr.write_buffer,
    					  bwr.write_size,
    					  &bwr.write_consumed);
    		......
    	}
    	if (bwr.read_size > 0) {
    		ret = binder_thread_read(proc, thread, bwr.read_buffer,
    					 bwr.read_size,
    					 &bwr.read_consumed,
    					 filp->f_flags & O_NONBLOCK);
    		trace_binder_read_done(ret);
    		if (!list_empty(&proc->todo))
    			wake_up_interruptible(&proc->wait);
    		if (ret < 0) {
    			if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
    				ret = -EFAULT;
    			goto out;
    		}
    	}
    	//拷贝内核数据，到用户空间。
    	if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
    		ret = -EFAULT;
    		goto out;
    	}
    out:
    	return ret;
    }
    ```

3. binder_thread_write函数
    ```c
    static int binder_thread_write(struct binder_proc *proc,
    			struct binder_thread *thread,
    			binder_uintptr_t binder_buffer, size_t size,
    			binder_size_t *consumed)
    {
    	uint32_t cmd;
    	void __user *buffer = (void __user *)(uintptr_t)binder_buffer;
    	void __user *ptr = buffer + *consumed;
    	void __user *end = buffer + size;

    	while (ptr < end && thread->return_error == BR_OK) {
    		//从用户空间，拷贝数据到内核空间。cmd = BC_TRANSACTION
    		if (get_user(cmd, (uint32_t __user *)ptr))
    			return -EFAULT;
    		ptr += sizeof(uint32_t);
    		......
    		switch (cmd) {
    		......
    		case BC_TRANSACTION:
    		case BC_REPLY: {
    			struct binder_transaction_data tr;
                //从用户空间拷贝数据，到内核空间。tr接收。
    			if (copy_from_user(&tr, ptr, sizeof(tr)))
    				return -EFAULT;
    			ptr += sizeof(tr);
    			binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
    			break;
    		}

    		......

    		default:
    			......//不识别的命令处理
    		}
    		*consumed = ptr - buffer;//标记消费了数据
    	}
    	return 0;
    }
    ```

4. binder_transaction函数
    ```c
    static void binder_transaction(struct binder_proc *proc,
    			       struct binder_thread *thread,
    			       struct binder_transaction_data *tr, int reply)//reply = false
    {
    	......
    	if (reply) {
    		......
    	} else {
    		//target.handle = 0(servicemanager的handle=0)
    		if (tr->target.handle) {
    			......
    		} else {
    			target_node = binder_context_mgr_node;
    			if (target_node == NULL) {
    				//不执行此分支
    				return_error = BR_DEAD_REPLY;
    				goto err_no_context_mgr_node;
    			}
    		}
    		e->to_node = target_node->debug_id;
    		target_proc = target_node->proc;
    		if (target_proc == NULL) {
    			//不执行此分支
    			return_error = BR_DEAD_REPLY;
    			goto err_dead_binder;
    		}
    		//security_binder_transaction默认返回0
    		if (security_binder_transaction(proc->tsk, target_proc->tsk) < 0) {
    			return_error = BR_FAILED_REPLY;
    			goto err_invalid_target_handle;
    		}
    		if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) {
    			......
    		}
    	}
    	if (target_thread) {
    		e->to_thread = target_thread->pid;
    		target_list = &target_thread->todo;
    		target_wait = &target_thread->wait;
    	} else {
    		target_list = &target_proc->todo;
    		target_wait = &target_proc->wait;
    	}
    	e->to_proc = target_proc->pid;

    	/* TODO: reuse incoming transaction for reply */
    	t = kzalloc(sizeof(*t), GFP_KERNEL);
    	if (t == NULL) {
    		......
    	}
    	binder_stats_created(BINDER_STAT_TRANSACTION);

    	tcomplete = kzalloc(sizeof(*tcomplete), GFP_KERNEL);
    	if (tcomplete == NULL) {
    		......
    	}
    	binder_stats_created(BINDER_STAT_TRANSACTION_COMPLETE);

    	t->debug_id = ++binder_last_id;
    	e->debug_id = t->debug_id;

    	......

    	if (!reply && !(tr->flags & TF_ONE_WAY))
    		t->from = thread;
    	else
    		t->from = NULL;
    	......
        //目标进程中申请空间。
    	t->buffer = binder_alloc_buf(target_proc, tr->data_size,
    		tr->offsets_size, !reply && (t->flags & TF_ONE_WAY));
    	if (t->buffer == NULL) {
    		......
    	}
    	t->buffer->allow_user_free = 0;
    	t->buffer->debug_id = t->debug_id;
    	t->buffer->transaction = t;
    	t->buffer->target_node = target_node;
    	trace_binder_transaction_alloc_buf(t->buffer);
    	if (target_node)
    		binder_inc_node(target_node, 1, 0, NULL);//增加引用。

    	offp = (binder_size_t *)(t->buffer->data +
    				 ALIGN(tr->data_size, sizeof(void *)));

    	if (copy_from_user(t->buffer->data, (const void __user *)(uintptr_t)
    			   tr->data.ptr.buffer, tr->data_size)) {
    		......//错误处理
    	}
    	if (copy_from_user(offp, (const void __user *)(uintptr_t)
    			   tr->data.ptr.offsets, tr->offsets_size)) {
    		......//错误处理
    	}
    	......
    	off_end = (void *)offp + tr->offsets_size;
    	off_min = 0;
    	for (; offp < off_end; offp++) {
    		struct flat_binder_object *fp;

    		if (*offp > t->buffer->data_size - sizeof(*fp) ||
    		    *offp < off_min ||
    		    t->buffer->data_size < sizeof(*fp) ||
    		    !IS_ALIGNED(*offp, sizeof(u32))) {
    			binder_user_error("%d:%d got transaction with invalid offset, %lld (min %lld, max %lld)\n",
    					  proc->pid, thread->pid, (u64)*offp,
    					  (u64)off_min,
    					  (u64)(t->buffer->data_size -
    					  sizeof(*fp)));
    			return_error = BR_FAILED_REPLY;
    			goto err_bad_offset;
    		}
    		fp = (struct flat_binder_object *)(t->buffer->data + *offp);
    		off_min = *offp + sizeof(struct flat_binder_object);
    		switch (fp->type) {
    		case BINDER_TYPE_BINDER:
    		case BINDER_TYPE_WEAK_BINDER: {
    			......
    		} break;
    		case BINDER_TYPE_HANDLE:
    		case BINDER_TYPE_WEAK_HANDLE: {
    			......
    		} break;

    		case BINDER_TYPE_FD: {
    			......
    		} break;

    		default:
    			binder_user_error("%d:%d got transaction with invalid object type, %x\n",
    				proc->pid, thread->pid, fp->type);
    			return_error = BR_FAILED_REPLY;
    			goto err_bad_object_type;
    		}
    	}
    	if (reply) {
    		......
    	} else if (!(t->flags & TF_ONE_WAY)) {
    		BUG_ON(t->buffer->async_transaction != 0);
    		t->need_reply = 1;
    		t->from_parent = thread->transaction_stack;
    		thread->transaction_stack = t;
    	} else {
    		BUG_ON(target_node == NULL);
    		BUG_ON(t->buffer->async_transaction != 1);
    		if (target_node->has_async_transaction) {
    			target_list = &target_node->async_todo;
    			target_wait = NULL;
    		} else
    			target_node->has_async_transaction = 1;
    	}
    	t->work.type = BINDER_WORK_TRANSACTION;
    	//添加到目标线程任务队列
    	list_add_tail(&t->work.entry, target_list);
    	tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
    	list_add_tail(&tcomplete->entry, &thread->todo);
    	if (target_wait)
    		wake_up_interruptible(target_wait);//唤醒等待队列
    	return;

    ......
    }
    ```

6. servicemanager进程被唤醒后，解析任务命令执行相应的动作。
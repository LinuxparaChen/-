# binder 通信流程
1. servicemanager服务
    ```C
    int main(int argc, char **argv)
    {
        struct binder_state *bs;
        //1. 打开binder驱动
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
        //1. 系统的open函数会调用驱动中的binder_open函数，真正打开驱动。
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
        //3. 调用系统的mmap函数映射虚拟内存，会调用binder驱动的binder_mmap函数。
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

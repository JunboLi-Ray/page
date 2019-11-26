# nginx原理分享
- [x] nginx介绍
- [x] 线上业务
- [x] nginx基本使用
- [x] 进程和信号
- [x] 内存管理
- [x] 连接管理
- [x] 事件和http处理
- [x] upstream
- [x] lua机制
- [x] healthcheck机制
- [x] 日志
- [x] 常见问题排查



# nginx介绍
nginx(读engine x)是一款高性能代理软件，采用c语言开发，采用模块化设计，有很多第三方模块，但是nginx模块开发非常困难，模块的设计并没有带来想像中的便利。官方网站是[http://nginx.org](http://nginx.org)。它有一个商业版本`NginxPlus`提供许多开源版没有模块和特性。

nginx做什么：
- tcp proxy
- http proxy
- grpc proxy
- 静态资源web服务器

借用网上一张图：
![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-11-02-084300.jpg)
nginx内存占用较少，经过近14年的迭代，功能强大且性能非常快。开始之前先了解一下当前公司的接入层结构。


# 线上业务
![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-24-092030.png)

### acccesspoint
- ssl 终止
- token查coreDB生成X-Putong-User-Id放到header
- 根据X-Testing-Group判断是否转发给ablb,转发给ablb时析增AB-GROUP头，即解析出的ab组名
- 按userid做限流
- 缓存token和userid的对应关系，降低db压力

### ablb
- 根据AB-GROUP转发给相应ab后端
- 没有AB-GROUP或找不到后端转发给生产环境

### 微服务lb
- grpc转发
- rest转发




# nginx基本使用

### 配置文件
配置文件样例：
```
user  root;
worker_processes  4;

error_log  logs/error.log  info;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';


    access_log  logs/access.log  main;
    proxy_http_version 1.1;
    proxy_set_header Connection "";

    upstream test {
       server 10.191.161.148:19890 max_conns=11;
       server 10.191.161.147:19890;
    }
    server {
        listen       80;
        server_name  localhost;

        access_log  logs/host.access.log  main;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
```
说明：
- 主配置文件nginx.conf，其它配置文件由nginx.conf引用
- 配置项由指令+指令参数组成2部分组成，即k-v对
- 指令参数分为简单和复杂两种
    - 简单指令参数：error_page 500 502 503 504 /50x.html;
    - 复杂指令参数：location /user  { return 200 ”ok”;}
- 指令上下文(以http为例)：
    - main
    - server
    - location

其中main的范围最大，location的范围最小，不同的指令应用不同的范围。Http相关的很多指令同时应用于多层。最内层的配置会继承高层的配置，所以如果有全局的配置，尽量配到高层，所有都会生效。

nginx的所有指令目录:
 - http://nginx.org/en/docs/dirindex.html

nginx的官方模块目录:
 - http://nginx.org/en/docs/




# 进程和信号

nginx启动后，可以通过ps命令查看它的进程
```
root$ ps -ef | grep nginx
root     11462     1  0 17:49 ?        00:00:00 nginx: master process /app/nginx/sbin/nginx -c /app/nginx/etc/nginx.conf
root     11463 11462  0 17:49 ?        00:00:00 nginx: worker process
root     11464 11462  0 17:49 ?        00:00:00 nginx: worker process
root     11465 11462  0 17:49 ?        00:00:00 nginx: cache manager process
```
实际上nginx的重启，退出都是通过信号实现的。当执行
```
/app/nginb/sbin/nginx -s reload
```
的时候其实是重新运行一个nginx可执行程序，这个新的程序向正在运行的`master`发送信号，然后master再向各worker发送信号，以执行各类操作。

注：新执行的进程通过读取pid文件获取master进程号，详细查看ngx_signal_process函数。


### 信号 
master支持的信号和功能：
signal|detail|-s 命令
-|-|-|
TERM/INT|	fast shutdown|stop
QUIT	|graceful shutdown|quit
HUP	|starting new worker processes with a new configuration, graceful shutdown of old worker processes|reload
USR1	|re-opening log files|reopen
USR2	|upgrading an executable file
WINCH	|graceful shutdown of worker processes


worker支持的信号和功能:
signal|detail
-|-
TERM/INT	|fast shutdown
QUIT	|graceful shutdown
USR1	|re-opening log files
WINCH	|abnormal termination for debugging (requires debug_points to be enabled)

### 进程模型
nginx有2种进程模型:
- `master-worker`模型
- 单`worker`模型

可以通过`master_process on | off;`指令来决定使用哪种模型，生产环境必须使用`master-worker`方式，以利用多核CPU，开发调试可以使用单`worker方式`。同时，可以使用`daemon of | off`决定nginx在前台或者后台运行。

补充：`daemon on;`nginx只是单纯的`fork`一个进程，让它摆脱shell前台，然后把前台进程退出，如果不使用systemd系统工具管理，它也有可能退出。



主进程执行几个流程：
- main
- 读取参数
- 继承句柄
- 初始化cycle
    - 解析配置文件
    - 初始化模块
    - 初始listening
    - 初始化共享内存
- 创建pid文件
- 创建worker


`master-worker`模型：

![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-28-100255.png)


由图中可知进程间通信的几个方式：
1. 共享内存
2. unix socket
    1. 进程的建立和句柄的传递
3. 信号
    1. 关闭，重启
4. 环境变量
    1. nginx热更新时通过环境变量把侦听socket的fd传递给新启动的nginx


`cycle`是一个重要概念，它是nginx的所有全局的变量的集中的地方。固名思义它表示nginx的循环，一次relod新建一个`cycle`变量。非常多的函数的第一个参数便是`cycle`

![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-28-100622.png)


现有架构下有一个问题：如果listen socket上有连接到来，所有的进程都会唤醒。

### 惊群
惊群指多个进程和线程在同时阻塞等待同一个事件时，如果这个事件发生，会唤醒所有的进程，但最终只可能有一个进程/线程对该事件进行处理，这种现象就是惊群：

nginx有几种方式避免惊群:
1. 使用`accept_mutex on;` 指令(全版本,早期版本默认开启)   
    原理：多个进程争抢全局共享内存锁，抢到的进程将通过epoll_add添加listen_fd的事件，没有抢到的删除事件，这样只有一个进程会被唤醒，规避了惊群。
2. 使用listen的reuseport参数（Nginx1.9.1 and kernel3.9+）   
    内核新特性，当多个socket都bind同一个端口号时，当有数据进来时内核通过负载均衡选取一个sockt，唤醒一个进程。
    
3. EPOLLEXCLUSIVE(nginx1.11.3 and kernel4.5)   
    epoll的新参数，内核改良的epoll。在支持的版本编译即可，无指令。



### 进程间互斥机制

nginx在worker内是无锁的，这也是Nginx效率高的原因之一。只有当涉及到进程间的操作时才会有锁的使用。
nginx 基于原子操作、信号量以及文件锁实现了一个简单高效的互斥锁。

原子操作：
```
ngx_atomic_cmp_set
ngx_atomic_fetch_add
```

互斥锁：
```
ngx_shmtx_lock
ngx_shmtx_trylock
ngx_shmtx_unlock
```
读写锁
```
ngx_rwlock_rlock
ngx_rwlock_wlock    
ngx_rwlock_unlock
```



nginx中使用锁的场景：
- ngx_accept_mutex
- ngx_shm_zone_t->ngx_slab_pool_t->mutex
- 启用zone指令后，upstream的peer选取（需要在各peer间计算权重，此处使用读写锁加大效率）
- 其它各zone的操作


# 内存管理

在高速代理软件中内存拷贝，内存分配往往成为瓶颈。从大方面讲nginx的内存管理分为`ngx_pool_t`和`ngx_slab_pool_t`两种。
### ngx_pool_t    
粗放式管理内存，只申请不释放，整个Pool做为单位进行释放。pool的分配规则相当简单：只要池的`end - last > size`就进行分配。如果申请内存小于pool大小，但是pool中无空间，这时新开辟一个Pool,挂接到pool链表，再分配，如果申请大于pool大小，直接malloc分配一个`ngx_pool_large_t`做为使用。释放的时候pool链上的所有内存都要释放，包括large申请的空间。`ngx_pool_t`的设计和使用使用它分配和回收非常高效。

常见操作：        
- ngx_create_pool(size)
- ngx_pcalloc(pool,size)
- ngx_destroy_pool(pool)


由于http的处理方式，每个请求到来需要申请内存，请求结束需要释放内存，故ngx_pool_t非常适用这个管理。每个请求到来都会创建一个pool(大小由指令request_pool_size设置，默认4k),然后所有请求维度的数据都从pool中申请，当这个http请求结束，整个pool释放掉，不用频繁释放。



![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-28-165957.jpg)

### [ngx_slab_pool_t](https://blog.csdn.net/qifengzou/article/details/11678115)

对于共享内存这类场景，内存大小一般是固定的，且释放时机不是确定的，如果继续采用`ngx_pool_t`进行管理会带来较大的内存负担。

对此，nginx使用slab内存进行更细分的管理，内存按大小分为不同的块，减少内存碎片的同时。


常见操作：
- ngx_slab_init(&pool)
- ngx_slab_alloc(pool,size)
- ngx_slab_free(pool,p)

目前所有的ngx_shm_zone_t申请的共享内存均使用slab进行管理：
- healthcheck的节点信息
- upstream zone
- limit_req
- cache索引信息
- 各种指令中带zone的




# 连接管理

对nginx而言，连接分为2类，一个是和前端一个是和后端，从信息流上讲一个前端连接对应多个后端连接。
![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-11-01-052337.png)


nginx对socket fd进行了以下抽象
- ngx_listening_s
    1. 代表一个侦听对象
- ngx_connection_s
    1. 包装了accept得到的句柄，代表一个tcp连接
- ngx_peer_connection_t
    1. 是对一个上游连接的抽象，它内部包含一个ngx_connection_s，是由负载均衡算法选出来的

### 连接对象管理 

连接的管理结构频繁申请和释放必须引起性能损失，故nginx对于`ngx_connection_s`的管理全部提前申请好，池子大小由`worker_connections`指令指定,upstream和downstream的连接都必须从这里申请。申请O(1)分配，效率很快。
![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-24-133503.png)


### 长连接池管理


所有的长连接都挂接在cycle->reusable_connections_queue上，包括downstream和upstream
```
ngx_reusable_connection(c,1) // 挂到queue上
ngx_reusable_connection(c,0) // 从queue上摘除
```


连接分配时先分配没有使用的，当free链无对象时，采用LRU强制从`reusable_connections_queue上`上关闭最多32个连接使用（如果够32则32如果不够全关）。


长连接分为二类：
- 和前端的长连接
    -  无须特殊管理
- 和后端的长连接
    -  单独启用新的队列
    -  负载均衡算法是选主机而非选连接
    -  选到主机后再遍历长连接cache取连接，因为连接采用头插法，故有热连接


### 常用操作

**ngx_get_connection** 
1. 从free_connections获取一个connection，然后初始化
2. 如果没有可用连接结构，则尝试从长连接队列获
3. 如果没有连接可用，报`worker_connections are not enough`

**ngx_close_connection** 
1. 删除该连接上的读和写超时事件（如果有）
2. 删除连接的读和写事件
3. 清空连接上的读和写异步队列
4. 从长连接队列删除该连接（如果是长连接）
5. 关闭fd

**ngx_free_connection**
1. 将使用的连接放回free_connections
2. 将cycle->files指针置空


**ngx_reusable_connection**
1. 参数reusable=1，把一个连接加入长连接队列
2. 参数reusable=0，从长连接队列删除该连接




# 事件和http处理
Nginx采用的「异步非阻塞」方式，具体到系统调用的话，就是像select/poll/epoll/kqueue这样的系统调用。它们提供了一种机制，让你可以同时监控多个事件，调用他们是阻塞的，但可以设置超时时间，在超时时间之内，如果有事件准备好了，就返回。

epoll是在Linux上关于事件的实现，而kqueue是OpenBSD或FreeBSD操作系统上采用类似epoll的事件模型。



```
ngx_process_events_and_timers:
    while(true):
        accept_mutex() # 获取accept_mutex锁
        ngx_epoll_process_events # epoll，ngx_time_update
        ngx_event_process_posted() #  处理ngx_posted_accept_events队列
        accept_mutex_unlock() # 释放accpet_mutex锁
        ngx_event_expire_timers # 处理超时事件
        ngx_event_process_posted # 处理ngx_posted_events本次
```

epoll的模型成功的把阻塞的网络转化成了非阻塞的异步事件。但是它也有缺陷：如果在事件处理中有阻塞行为，那么nginx的效率就会非常低下。为此新版本的nginx中针对文件的读写进行了更高一步的优化，启了用线程。

由于某个进程会抢到`accept_mutex`锁，则它的处理时间会较其它进程大，且持锁期间没有其它进程能够accept新连接，因此持锁时间越小越好，为此nginx采用两个队列来把可以延后的操作延后处理。

在抢到accpet_mutex锁的进程中会使用以下两个队列：
- ngx_posted_accept_events
    - accept事件队列
    - 为了不影响其它已经请求的处理时延，新连接的处理放在其它请求处理之后进行，但是必须放在锁释放之前，否则锁一旦释放，其它进程就有机会获取锁，并accept走所有新连接。导致连接不均衡。
- ngx_posted_events
    - 读写事件的后处理队列
    - 可以放在锁释放之后处理，本进程上的其它连接的读写事件都会延迟到此时处理。

### 事件处理阶段
epoll事件的系统定义：
```
typedef union epoll_data {
    void *ptr;
    int fd;
    __uint32_t u32;
    __uint64_t u64;
} epoll_data_t;

struct epoll_event {
    __uint32_t events; /* Epoll events */
    epoll_data_t data; /* User data variable */
};
```

epoll 的data字段一直为ngx_http_connection_t，所以每当epoll_wait触发时，很容易能拿到当前连接的信息，进而做下一步处理。

nginx在epoll基础上抽象了一层，即连接的读写事件
```
    ngx_epoll_process_events:
        events = epoll_wait()
        for ev in events:
            conn = ev.data
            if EPOLLIN:
                  conn.rev.handler();
            if EPOLLOUT:
                  conn.wev.handler()
```

而rev和wev即读写事件，它的hanlder定义如下：
```
struct ngx_event_s {
    void   *data;      // ngx_connection_t
    ngx_event_handler_pt  handler;
   ...
}
typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);
```

故nginx所有函数以`ngx_event_t *ev`作为参数的都是connection的事件处事函数，例：
```
void ngx_event_accept(ngx_event_t *ev)
static void ngx_http_wait_request_handler(ngx_event_t *rev)
static void ngx_http_request_handler(ngx_event_t *ev)
static void ngx_http_process_request_line(ngx_event_t *rev)
static void ngx_http_process_request_headers(ngx_event_t *rev)
```
上述其实是按conn->rev->handler的变化顺序来的。

**问题：**
accept事件回调中，nginx怎么知道这个连接是处理http还是http2或者tcp?

答： ngx_listening_t有一个handler挂接了高层协议，是高层协议的处理化函数：
```
ls->handler = ngx_http_init_connection; //http & http2
ls->handler = ngx_mail_init_connection; // mail
ls->handler = ngx_stream_init_connection; // stream模块
```

故当侦听socket收到请的连接时，
```
ngx_event_accept(ev):
    conn = ev.data
    conn->ls->handler(c)
    
```

当连接上第一次有数据时：
```
ngx_http_wait_request_handler(ev):
    conn = ev.data
    conn->data = ngx_http_create_request(conn);
```    
当过程进入ngx_http_process_request_headers时，逻辑进一步细化为，请求的读写事件。
```
    ngx_http_process_request_headers(ev):
        conn = ev->data
        req  = conn->data
        if conn->write:
            req->write_event_handler(r)
        if conn->read:
            req->read_event_handler
```

故所有为以下原型的也都是读写回调函数
```
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);
```
例：
```
void ngx_http_block_reading(ngx_http_request_t *r)
void ngx_http_core_run_phases(ngx_http_request_t *r)
```

最后一个回调是`ngx_http_core_run_phases`这时进入nginx的阶段处理。
### http的处理阶段
Nginx将一个HTTP请求分成多个阶段，以模块为单位进行处理。这样做的好处是使处理过程更加灵活、降低耦合度。HTTP框架将处理分成了11个阶段，各个阶段可以包含任意多个HTTP模块并以流水线的方式处理请求。这11个HTTP阶段如下所示

```
typedef enum {
    NGX_HTTP_POST_READ_PHASE = 0,   // 接收到完整的HTTP头部后处理的阶段
 
    NGX_HTTP_SERVER_REWRITE_PHASE,  // URI与location匹配前，修改URI的阶段，用于重定向
 
    NGX_HTTP_FIND_CONFIG_PHASE,     // 根据URI寻找匹配的location块配置项
    NGX_HTTP_REWRITE_PHASE,         // 上一阶段找到location块后再修改URI
    NGX_HTTP_POST_REWRITE_PHASE,    // 防止重写URL后导致的死循环
 
    NGX_HTTP_PREACCESS_PHASE,       // 下一阶段之前的准备
 
    NGX_HTTP_ACCESS_PHASE,          // 让HTTP模块判断是否允许这个请求进入Nginx服务器
    NGX_HTTP_POST_ACCESS_PHASE,     // 向用户发送拒绝服务的错误码，用来响应上一阶段的拒绝
 
    NGX_HTTP_TRY_FILES_PHASE,       // 为访问静态文件资源而设置
    NGX_HTTP_CONTENT_PHASE,         // 处理HTTP请求内容的阶段，大部分HTTP模块介入这个阶段
 
    NGX_HTTP_LOG_PHASE              // 处理完请求后的日志记录阶段

}
```

整个过程大致如下：

![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-22-034825.jpg)

每个指令都有一个执行阶段，这个阶段有时容易出现一些奇怪的问题，使用时最好测试充分。

# upstream

添加upstream，upstream是一组后端的集合。
```
upstream srv_gateway_tt{
      zone  srv_gateway_zone 1k;
      server 10.0.0.77 weight=5 max_conns=10;
      server 10.0.0.88 max_fails=3 fail_timeout=30s;;
      keepalive 100；   
}
```
keepalive指令
- 开启和upstream的长连接机制
- 指定cache的大小
- 它不限定连接数，当连接池不够用，用LRU关闭连接


开启长连接会单独启用一个队列来缓存连接信息：
![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-27-070950.png)


**补充：**  
如果要和upstream使用长连接，需要满足两个条件
1. 和upstream间版本为http/1.1
2. upstream使用keepalive指令开启连接cache

> 如果只满足1，则nginx会强制关闭连接，如果只满足2，upstream server会关闭连接。



upstream支持的负载均衡算法
- [权重轮询](http://note.youdao.com/noteshare?id=e413cc77afcf5dadce82b2df2e43687c)
    - 按权重在节点间轮训，并保证请求在各节点间均衡。节点失败会降低权重,max_fails次后降为0，然后摘除
- ip_hash
    - 按C类网址哈希，有较大缺陷，ip地址前3字节相同的会哈希到同一台机器
    - 哈希算法较为简单只计算前3字节： hash = (hash * 113 + ip_addr[i]) % 6271， 随机测试其分布并不均匀:
![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-11-01-104240.jpg)
    - 这么设计的目的是考虑使用isp的用户，如果用户重启ip可能发生变化，但一般仍旧在同一个网络
- hash
    - 通用的hash算法,分为一至性哈希不非一至算法
    ![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-11-01-121247.png)
    - 节点中间down机不会影响分布，主要适用场景为后端为cache场景，防止新加或删除节点rehash而扰乱cache命中率
- least_conn
    - 最小连接，使用conns/weight做为计算单位，选取最小的进行选择





**server指令的关键参数**
- weight=number
    - 设置权重，默认1
- max_conns=number
    - 设置一个server的连接数上限
    - 如果没有zone配置，单server总连接实际上为max_conns*worker_num
    - 如果有zone，则这个设置是全局的，多个进程间也只有这么多连接数
- max_fails=number
    - 默认值为1，0为关闭该功能
    - 在`fail_timeout`时间内失败`max_fails`次，则标记server为`down`状态
- fail_timeout=time
    -  默认10s，配合max_fails使用
    -  节点设置为down后，惩罚fail_timeout长时间
    -  fail_timeout的时间起点为，在每次节点被选中时且离上次更新时间超过了fail_timeout（通过（peer->checked变量记录）
- backup
    -   指明一个节点为冷备，当所有其它结点不可用时，此节点会被使用
- down
    -   停用一个节点

**转发设置**
- proxy_next_upstream
    - 指定什么情况下向后端转发可按err,timeout,status_code
    - non_idempotent，正常下非等幂请求(POST,PATCH)不会重试，此标志会强制重试
    - 重试只发生在请求没有发给前端的时候，请求处理到一半失败，是不会重试的。
- proxy_next_upstream_timeout
    -   指定在多长时间内进行重试，时间起点为http请求到达时
- proxy_next_upstream_tries
    -   指定一个请求可以重试多少次
    -   重试次数不会大于server总数（解析出来的主机数，不是server指令的个数）


### cache
cache管理的指令大概分为2类：
- 缓存后端请求
    - proxy_cache
    - fastcgi_cache
    - xxxxx_cache
    - grpc不支持
- 缓存打开文件句柄
    - open_file_cache

无论哪种，都只是缓存管理结构而不是缓存文件内容。


配置举例：

```
http {
roxy_cache_path /app/nginx/cache keys_zone=test:1m;
    server {
        listen 80;    
    
        location ~ /token/(?<access_token>[0-9a-f]+) {
            proxy_cache_valid 30m;
            proxy_cache test;
            proxy_cache_key "$access_token";
            proxy_set_header Host       $host;
        
            proxy_pass http://test;
        }
    }
}
```

cache的的管理形式如下：

![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-11-02-060158.png)

由于cache的只读特性，对于操作系统BufferCache有较高命中率，此时的主要开销是比较昂贵的`open`系统调用，故nginx又进一步增加了open_file_cache以减少`open`系统调用。



# lua机制

lua使用举例
```
location /lua {
    set $test "hello, world.";
    content_by_lua '
        ngx.header.content_type = "text/plain";
        ngx.say(ngx.var.test);
    ';
}
```

lua是c语言的胶水语言，轻量，性能快，且可以与c语言函数互相调用。二者结合可以发挥lua的灵活同时兼顾c语言的高性能。

OpenResty是nginx的一个lua打包解决方案。我们现在使用的只是单独编译的[ngx_lua](https://github.com/openresty/lua-nginx-module)模块。

ngx_lua涉及很多指令，分别在nginx的不同阶段注册了不同的handler,所以可以根据需要使用它们。
```
access_by_lua
set_by_lua
rewrite_by_lua
content_by_lua
header_filter_by_lua
body_filter_by_lua
body_filter_by_lua
balancer_by_lua_block
```
全局图：
![](https://cloud.githubusercontent.com/assets/2137369/15272097/77d1c09e-1a37-11e6-97ef-d9767035fc3e.png)





# healthcheck机制
### 源理
本模块属于tengine开发第三方模块。主要利用nginx提供的事件机制，对upstream进行探测。使用此模块需要对nginx源码进行pache。

所有upstream的状态在shm中进行管理，当有进程正在进行探测时，其它进程不探测，只保证每个时刻只有一个进程探测。探测分为两类：
1. 心跳    
定时发送心跳，可以指定协议类型，发送内容，失败次数，达到指定失败次数后结点标记为down。同时也可指定超时时间，在结点超期间不会重复进行探测。
2. 长连接
长连接情形下，不会发送心跳，只是单纯维持连接，此连接上没有数据流通。当对端发生异常强制关闭连接时健康检查模块感知连接断开，设置upstream为down。（正常关闭下会有FIN包，epoll会触发读事件，可读空）

![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-19-074355.jpg)

# 日志
日志有两个指令:
###  access_log
简单用法
> access_log path format gzip[=level] [buffer=size [flush=time]]

```
log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" "$http_x_forwarded_for"';
                  
access_log  logs/access.log  main;
```
如果不开启缓存，每次都是直接写文件，对性能有一定损失。

access_log运行的LOG阶段，每个请求都会打印。


### error_log

nginx的日志通过error_log指令指定,同时可以指定日志等级。 debug信息，info信息等全在error日志中。
```
error_log  logs/error.log  info;
```

nginx的error日志格式:
 `what happend` while `doing what`


# 常见问题排查


### 1. upstream prematurely closed connection while reading response header from upstream
上游超时，强制关闭连接
![](http://takakawa-md.oss-cn-beijing.aliyuncs.com/md/2018-10-28-180102.jpg)
### 2. worker_connections are not enough
```
2018/07/16 12:03:01 [alert] 87183#0: *7191002208 512 worker_connections are not enough while connecting to upstream, client: 10.189.2.55, server: , request: "POST /user.UserCounterService/UpdateWithDeltaWithReturning HTTP/2.0", upstream: "grpc://10.189.101.54:21258", host: "grpc.usercounter.lb:21258"
2018/07/16 12:03:01 [alert] 87183#0: *7191002208 512 worker_connections are not enough while connecting to upstream, client: 10.189.2.55, server: , request: "POST /user.UserCounterService/UpdateWithDeltaWithReturning HTTP/2.0", upstream: "grpc://10.189.101.63:21258", host: "grpc.usercounter.lb:21258"
2018/07/16 12:03:01 [alert] 87183#0: *7191002208 512 worker_connections are not enough while connecting to upstream, client: 10.189.2.55, server: , request: "POST /user.UserCounterService/UpdateWithDelta HTTP/2.0", upstream: "grpc://10.189.3.42:21258", host: "grpc.usercounter.lb:21258"
```
同时会导致业务grpc 报err
```
code = Internal desc = transport: received the unexpected content-type \"text/html\"
```

修改event里的`worker_connections  1024000;`解决

### 3. connect() failed
```
2018/07/12 15:32:55 [error] 132847#0: *184446141 connect() failed (111: Connection refused) while connecting to upstream, client: 10.189.8.44, server: , request: "GET /user-counters/150644691 HTTP/1.1", upstream: "http://10.189.4.41:21260/user-counters/150644691", host: "restapi.usercounter.lb:21260"
2018/07/12 15:32:56 [error] 132840#0: *184433451 connect() failed (111: Connection refused) while connecting to upstream, client: 10.189.8.36, server: , request: "GET /user-counters/158919679 HTTP/1.1", upstream: "http://10.189.4.41:21260/user-counters/158919679", host: "restapi.usercounter.lb:21260"
2018/07/12 15:32:56 [error] 132873#0: *184428780 connect() failed (111: Connection refused) while connecting to upstream, client: 10.189.8.44, server: , request: "GET /user-counters/133024575 HTTP/1.1", upstream: "http://10.189.4.41:21260/user-counters/133024575", host: "restapi.usercounter.lb:21260"
```
后端端口不存在，一般服务发布出现，nginx会迅速重试，所以服务会成功

### 4. 退化为http1.0
nginx默认为1.0，故如果遇到后到端请求退化为http1.0
需要在server中增加以下配置
```
    proxy_http_version 1.1;
    proxy_set_header Connection "";
```
### 5. 到后端，无法通过Host获取到请求域名
nginx默认会修改Host为upstream的名字，故需要在server中增加
```
proxy_set_header           Host $http_host;
```
### 6. no live upstreams while connecting to upstream

当upstream节点全部不可用时出现此错误

### 7. upstream timed out (110: Connection timed out) while connecting to upstream

连接超时，一般网络有问题会导致此报错

# 谢谢
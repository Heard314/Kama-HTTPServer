#include "../../include/ssl/SslConnection.h"
#include <muduo/base/Logging.h>
#include <openssl/err.h>

namespace ssl
{

// 自定义 BIO 方法
static BIO_METHOD* createCustomBioMethod() 
{
    BIO_METHOD* method = BIO_meth_new(BIO_TYPE_MEM, "custom");
    BIO_meth_set_write(method, SslConnection::bioWrite);
    BIO_meth_set_read(method, SslConnection::bioRead);
    BIO_meth_set_ctrl(method, SslConnection::bioCtrl);
    return method;
}

SslConnection::SslConnection(const TcpConnectionPtr& conn, SslContext* ctx)
    : ssl_(nullptr)
    , ctx_(ctx)
    , conn_(conn)
    , state_(SSLState::HANDSHAKE)
    , readBio_(nullptr)
    , writeBio_(nullptr)
    , messageCallback_(nullptr)
    , handshakeWantWrite_(false)
{
    assert(ctx_!=nullptr);
    // 创建 SSL 对象
    ssl_ = SSL_new(ctx_->getNativeHandle());
    if (!ssl_) {
        LOG_ERROR << "Failed to create SSL object: " << ERR_error_string(ERR_get_error(), nullptr);
        return;
    }

    // 创建 custom BIO method
    BIO_METHOD* customMethod = createCustomBioMethod();
    if (!customMethod) {
        LOG_ERROR << "Failed to create custom BIO method";
        SSL_free(ssl_);
        ssl_ = nullptr;
        return;
    }

    // 创建 BIO
    readBio_ = BIO_new(BIO_s_mem());
    writeBio_ = BIO_new(BIO_s_mem());
    
    if (!readBio_ || !writeBio_) {
        LOG_ERROR << "Failed to create BIO objects";
        SSL_free(ssl_);
        ssl_ = nullptr;
        return;
    }

    SSL_set_bio(ssl_, readBio_, writeBio_);
    SSL_set_accept_state(ssl_);  // 设置为服务器模式

//    // 将 SslConnection 对象设置为 BIO 的 data
//    BIO_set_data(readBio_, this);
//    BIO_set_data(writeBio_, this);

    // 设置 SSL 选项，以下两个东西会导致SSL_do_handshake发生段错误
//    SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
//    SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE);
    
//    ssl::SslConnection 应该通过其自身的 handleRead 和 handleWrite 方法与底层的 TcpConnection 进行交互，而不是通过回调函数
//    conn_->setMessageCallback(
//        std::bind(&SslConnection::onRead, this, std::placeholders::_1,
//                 std::placeholders::_2, std::placeholders::_3));
//    conn_->setWriteCallback(
//            std::bind(&SslConnection::onWrite, this));
}

SslConnection::~SslConnection() 
{
    if (ssl_) 
    {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);  // 这会同时释放 BIO
        ssl_ = nullptr;
    }
}

void SslConnection::handleHandshake()
{
    assert(ssl_!=nullptr);
    char buf[DEFAULT_BUF_SIZE];

    int ret = SSL_do_handshake(ssl_);

    if (ret == 1) {
        state_ = SSLState::ESTABLISHED;
        LOG_INFO << "SSL handshake completed successfully";
        LOG_INFO << "Using cipher: " << SSL_get_cipher(ssl_);
        LOG_INFO << "Protocol version: " << SSL_get_version(ssl_);
        return;
    }

    int err = SSL_get_error(ssl_, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            int len;
            do
            {
                len = BIO_read(readBio_, buf, sizeof(buf));
                if(len > 0)
                {
                    // TODO 发出握手信息
                }
                else if (!BIO_should_retry(writeBio_))
                {
                    state_ = SSLState::ERROR;
                    break;
                }
            } while(len > 0)

//            // 需要读取数据，注册读事件
//            if (messageCallback_) {
//                // 握手完成后，如果缓冲区有待处理的数据，可以尝试读取
//                if (readBuffer_.readableBytes() > 0) {
//                    BufferPtr buffer(new muduo::net::Buffer);
//                    buffer->append(readBuffer_.peek(), readBuffer_.readableBytes());
//                    onRead(conn_, buffer, muduo::Timestamp::now());
//                    readBuffer_.retrieveAll(); // 清空 readBuffer_，因为数据已经传递给 onRead
//                }
//            } else {
//                LOG_WARN << "No message callback set after SSL handshake for " << conn_->peerAddress().toIpPort();
//            }
//            flushWriteBio(); // 确保发送完握手数据
//            if(!conn_->isReading())
//            {
//                conn_->startRead();
//            }
//            break;
//
//            LOG_DEBUG << "SSL_ERROR_WANT_WRITE during handshake for " << conn_->peerAddress().toIpPort();
//            handshakeWantWrite_ = true;
//            // 依赖 flushWriteBio 在后续发送数据时处理
//            break;

        default: {
            // 获取详细的错误信息
            char errBuf[256];
            unsigned long errCode = ERR_get_error();
            ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
            LOG_ERROR << "SSL handshake failed: " << errBuf;
            state_ = SSLState::ERROR;
            conn_->shutdown();  // 关闭连接
            break;
        }
    }
}

int SslConnection::transferToBioAndRead(muduo::net::Buffer* buffer)
{
    char buf[DEFAULT_BUF_SIZE];
    int n;

    while (buffer->readableBytes() > 0) {
        size_t len_to_write = buffer->readableBytes();
        const char* src = buffer->peek(); // 获取可读数据的起始地址

        n = BIO_write(readBio_, src, len_to_write);

        if (n <= 0) {
            // 处理 BIO_write 错误
            return -1; /* assume bio write failure is unrecoverable */
        }

        buffer->retrieve(n); // 移动读指针，标记已写入 BIO 的数据

        // 准备 SSL_read 读取数据，握一下手
        if (!SSL_is_init_finished(ssl_)) {
            handleHandshake();
            if (state_ == SSLState::ERROR)
                return -1;
            if (!SSL_is_init_finished(ssl_))
                return 0;
        }

        /* The encrypted data is now in the input bio so now we can perform actual
         * read of unencrypted data. */
        // 从 ssl 中读出来解密后的客户端输入数据，并进行输出
        do {
            n = SSL_read(ssl_, buf, sizeof(buf));
            if (n > 0)
            {
                if(decryptedBuffer_)
                {
                    writeDecryptedBuffer(buf,n);
                }
                else
                {
                    LOG_ERROR << "decryptedBuffer_ do not exist!" <<"\n";
                    return -1;
                }
            }
        } while (n > 0);

        enum SSLError status = getLastError(n);

        /* Did SSL request to write bytes? This can happen if peer has requested SSL
         * renegotiation. */
        //! 在处理完接收到的数据后，本地的 OpenSSL 引擎可能需要发送一些控制消息或握手消息给对端。
        if (status == WANT_WRITE || status == WANT_READ)
            do {
                n = BIO_read(writeBio_, buf, sizeof(buf));
                if (n > 0)
                    //TODO 握手消息怎么发
                    queueEncryptedBytes(buf, n);
                else if (!BIO_should_retry(writeBio_)) {
                    // 处理 BIO_read 错误
                    return -1;
                }
            } while (n > 0);

        if (status == SSLSTATUS_FAIL)
            return -1;
    }

    return 0;
}

/* Process outbound unencrypted data that is waiting to be encrypted.  The
* waiting data resides in encrypt_buf.  It needs to be passed into the SSL
* object for encryption, which in turn generates the encrypted bytes that then
* will be queued for later socket write. */
int SslConnection::encryptAndBufferWrite(muduo::net::Buffer& buffer)
{
    char buf[DEFAULT_BUF_SIZE];
    enum SSLError status;
    int n;

    if (!SSL_is_init_finished(ssl_))
        return 0;

    while (buffer.readableBytes() > 0) {
        // 向 ssl 写入待加密数据
        size_t len_to_encrypt = buffer.readableBytes();
        const char* data_to_encrypt = buffer.peek();

        n = SSL_write(ssl_, data_to_encrypt, len_to_encrypt);
        status = get_sslstatus(n);

        if (n > 0) {
            // 消费掉已经加密的数据
            buffer.retrieve(n);

            // 读取 wbio，得到已加密的数据
            do {
                n = BIO_read(writeBio_, buf, sizeof(buf));
                if (n > 0)
                    // 放到写缓存中，准备发送出去
                    // TODO 写出消息 目前的实现是放到写缓存中，然后定时检查写缓存中内容并发送
                else if (!BIO_should_retry(writeBio_))
                    return -1;
            } while (n > 0);
        }

        if (status == ERROR)
            return -1;

        if (n == 0)
            break;
    }
    return 0;
}

void SslConnection::startHandshake() 
{
    SSL_set_accept_state(ssl_);
    handleHandshake();
}

void SslConnection::send(const void* data, size_t len) 
{
    if (state_ != SSLState::ESTABLISHED) {
        LOG_ERROR << "Cannot send data before SSL handshake is complete";
        return;
    }
    
    int written = SSL_write(ssl_, data, len);
    if (written <= 0) {
        int err = SSL_get_error(ssl_, written);
        LOG_ERROR << "SSL_write failed: " << ERR_error_string(err, nullptr);
        return;
    }

    flushWriteBio();
}

void SslConnection::onRead(const TcpConnectionPtr& conn, BufferPtr buf, 
                         muduo::Timestamp time) 
{
    LOG_DEBUG<<"onRead has been invoked.\n";
    if (state_ == SSLState::HANDSHAKE) {
        // 将 muduo buffer 中的数据追加到 SslConnection 的 readBuffer_
        BIO_write(readBio_, buf->peek(), buf->readableBytes());
        // 移动 muduo buffer 的读指针，表明数据已被 SslConnection 接收
        buf->retrieve(buf->readableBytes());
        handleHandshake();
        return;
    }
    else if (state_ == SSLState::ESTABLISHED)
    {
        // 将 muduo buffer 中的数据追加到 SslConnection 的 readBuffer_
        readBuffer_.append(buf->peek(), buf->readableBytes());
        buf->retrieveAll();

        // 解密数据
        char decryptedData[4096];
        int ret = SSL_read(ssl_, decryptedData, sizeof(decryptedData));
        if (ret > 0) {
            // 创建新的 Buffer 存储解密后的数据
            muduo::net::Buffer decryptedBuffer;
            decryptedBuffer.append(decryptedData, ret);
            
            // 调用上层回调处理解密后的数据
            if (messageCallback_) {
                messageCallback_(conn, &decryptedBuffer, time);
            }
        }
        else if(ret < 0)
        {
            int err = SSL_get_error(ssl_, ret);
            if (err != SSL_ERROR_WANT_READ) {
                LOG_ERROR << "SSL_read error after handshake: " << ERR_error_string(err, nullptr);
                handleError(getLastError(ret));
            }
        }
        else
        {
            // SSL_read 返回 0 表示连接已关闭
            LOG_INFO << "SSL connection closed by peer";
            conn_->shutdown();
            state_ = SSLState::SHUTDOWN;
        }
    }
}



//void SslConnection::handleWrite()
//{
//    if (state_ == SSLState::HANDSHAKE && handshakeWantWrite_) {
//        handshakeWantWrite_ = false;
//        handleHandshake();
//    } else if (state_ == SSLState::ESTABLISHED) {
//        flushWriteBio();
//        // 处理应用层写操作在 send 函数中完成
//    }
//}

void SslConnection::flushWriteBio()
{
    char buf[4096];
    int pending;
    while ((pending = BIO_pending(writeBio_)) > 0) {
        int bytes = BIO_read(writeBio_, buf,
                             std::min(pending, static_cast<int>(sizeof(buf))));
        if (bytes > 0) {
            conn_->send(buf, bytes);
        }
    }
}

SSLError SslConnection::getLastError(int ret) 
{
    int err = SSL_get_error(ssl_, ret);
    switch (err) 
    {
        case SSL_ERROR_NONE:
            return SSLError::OK;
        case SSL_ERROR_WANT_READ:
            return SSLError::WANT_READ;
        case SSL_ERROR_WANT_WRITE:
            return SSLError::WANT_WRITE;
        case SSL_ERROR_SYSCALL:
            return SSLError::SYSCALL;
        case SSL_ERROR_SSL:
            return SSLError::SSL_ERR;
        default:
            return SSLError::ERR;
    }
}

void SslConnection::handleError(SSLError error) 
{
    switch (error) 
    {
        case SSLError::WANT_READ:
        case SSLError::WANT_WRITE:
            // 需要等待更多数据或写入缓冲区可用
            break;
        case SSLError::SSL:
        case SSLError::SYSCALL:
        case SSLError::UNKNOWN:
            LOG_ERROR << "SSL error occurred: " << ERR_error_string(ERR_get_error(), nullptr);
            state_ = SSLState::ERROR;
            conn_->shutdown();
            break;
        default:
            break;
    }
}

int SslConnection::bioWrite(BIO* bio, const char* data, int len) 
{
    LOG_DEBUG<<"bioWrite has been invoked.\n";
    SslConnection* sslConn = static_cast<SslConnection*>(BIO_get_data(bio));
    if (!sslConn || !sslConn->conn_) return -1;

    sslConn->conn_->send(data, len);
    return len;
}

int SslConnection::bioRead(BIO* bio, char* data, int len) 
{
    LOG_DEBUG<<"bioRead has been invoked.\n";
    SslConnection* sslConn = static_cast<SslConnection*>(BIO_get_data(bio));
    if (!sslConn) return -1;

    size_t readable = sslConn->readBuffer_.readableBytes();
    if (readable == 0) 
    {
        return -1;  // 无数据可读
    }

    size_t toRead = std::min(static_cast<size_t>(len), readable);
    memcpy(data, sslConn->readBuffer_.peek(), toRead);
    sslConn->readBuffer_.retrieve(toRead);
    return toRead;
}

long SslConnection::bioCtrl(BIO* bio, int cmd, long num, void* ptr)
{
    LOG_DEBUG<<"bioCtrl has been invoked.\n";
    switch (cmd)
    {
        case BIO_CTRL_FLUSH:
            return 1;
        case BIO_CTRL_DGRAM_SET_CONNECTED:
            return 1;
        case BIO_CTRL_DGRAM_GET_PEER:
            return -1; // Not applicable for TCP
        case BIO_CTRL_DGRAM_SET_PEER:
            return -1; // Not applicable for TCP
        case BIO_C_SET_FD:
            return 1;
        case BIO_C_GET_FD:
            return -1; // We are using memory BIO
        case BIO_CTRL_DUP:
            return 0;
//        case BIO_CTRL_WPENDING:
//            return BIO_pending(BIO_get_data(bio));
//        case BIO_CTRL_PENDING:
//            return BIO_pending(BIO_get_data(bio));
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
            return 0;
        default:
            return 0;
    }
}

//void SslConnection::onEncrypted(const char* data, size_t len)
//{
//    writeBuffer_.append(data, len);
//    conn_->send(&writeBuffer_);
//}
//
//void SslConnection::onDecrypted(const char* data, size_t len)
//{
//    decryptedBuffer_.append(data, len);
//}

} // namespace ssl 
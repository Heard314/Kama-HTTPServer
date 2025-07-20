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

    SSL_set_accept_state(ssl_);  // 设置为服务器模式
    SSL_set_bio(ssl_, readBio_, writeBio_);


    // 设置 SSL 选项，以下两个东西会导致SSL_do_handshake发生段错误
//    SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
//    SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE);
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
            break;
        case SSL_ERROR_WANT_WRITE:
            int len;
            do
            {
                len = BIO_read(writeBio_, buf, sizeof(buf));
                if(len > 0)
                {
                    if (!SSL_is_init_finished(ssl_))
                    {
                        conn_->send(buf,len);
                    }
                    else
                    {
                        LOG_ERROR<<"Error: Received data in handshake phase after handshake is finished"<<"\n";
                    }
                }
                else if (!BIO_should_retry(writeBio_))
                {
                    state_ = SSLState::ERROR;
                    break;
                }
            } while(len > 0);
                break;

        default: {
            // 获取详细的错误信息
            char errBuf[2560];
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

        // 准备
        if (!SSL_is_init_finished(ssl_)) {
            handleHandshake();
            if (state_ == SSLState::ERROR)
                return -1;
//            if (!SSL_is_init_finished(ssl_))
//                return 0;
        }

        size_t len_to_write = buffer->readableBytes();
        const char* src = buffer->peek(); // 获取可读数据的起始地址

        n = BIO_write(readBio_, src, len_to_write);

        if (BIO_flush(readBio_) != 1)
        {
            LOG_ERROR << "Error flushing source BIO\n";
        }
        if (n <= 0) {
            // 处理 BIO_write 错误
            return -1; /* assume bio write failure is unrecoverable */
        }

        buffer->retrieve(n); // 移动读指针，标记已写入 BIO 的数据

        /* The encrypted data is now in the input bio so now we can perform actual
         * read of unencrypted data. */
        // 从 ssl 中读出来解密后的客户端输入数据，并进行输出

        do {
            n = SSL_read(ssl_, buf, sizeof(buf));
            if (n > 0)
            {
                writeDecryptedBuffer(buf,n);
            }
        } while (n > 0);

        enum SSLError status = getLastError(n);

        /* Did SSL request to write bytes? This can happen if peer has requested SSL
         * renegotiation. */
        //! 在处理完接收到的数据后，本地的 OpenSSL 引擎可能需要发送一些控制消息或握手消息给对端。
        if (status == SSLError::WANT_WRITE || status == SSLError::WANT_READ)
        {
            do {
                n = BIO_read(writeBio_, buf, sizeof(buf));
                if (n > 0)
                    conn_->send(buf,n);
                else if (!BIO_should_retry(writeBio_)) {
                    // 处理 BIO_read 错误
                    return -1;
                }
            } while (n > 0);
        }

        if (status == SSLError::ERR)
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
        status = getLastError(n);

        if (n > 0) {
            // 消费掉已经加密的数据
            buffer.retrieve(n);

            // 读取 wbio，得到已加密的数据
            do {
                n = BIO_read(writeBio_, buf, sizeof(buf));
                if (n > 0)
                    // 放到写缓存中，准备发送出去
                    writeReadySendBuffer(buf,n);
                else if (!BIO_should_retry(writeBio_))
                    return -1;
            } while (n > 0);
        }

        if (status == SSLError::ERR)
            return -1;

        if (n == 0)
            break;
    }
    return 0;
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
        case SSLError::ERR:
        case SSLError::SYSCALL:
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
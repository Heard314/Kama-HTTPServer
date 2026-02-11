#include "../../include/ssl/SslConnection.h"
#include <muduo/base/Logging.h>
#include <openssl/err.h>

namespace ssl
{

static void logOpenSslErrors(const char* prefix)
{
    unsigned long e = 0;
    while ((e = ERR_get_error()) != 0)
    {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        LOG_ERROR << prefix << ": " << buf;
    }
}

SslConnection::SslConnection(const TcpConnectionPtr& conn, SslContext* ctx)
    : ssl_(nullptr)
    , ctx_(ctx)
    , conn_(conn)
    , state_(SSLState::HANDSHAKE)
    , readBio_(nullptr)
    , writeBio_(nullptr)
{
    ssl_ = SSL_new(ctx_->getNativeHandle());
    if (!ssl_) {
        LOG_ERROR << "SSL_new failed";
        logOpenSslErrors("SSL_new");
        return;
    }

    readBio_  = BIO_new(BIO_s_mem());
    writeBio_ = BIO_new(BIO_s_mem());
    if (!readBio_ || !writeBio_) {
        LOG_ERROR << "BIO_new failed";
        logOpenSslErrors("BIO_new");
        if (ssl_) SSL_free(ssl_);
        ssl_ = nullptr;
        return;
    }

    // 让 readBio_ 在无数据时返回 -1，触发 WANT_READ
    BIO_set_mem_eof_return(readBio_, -1);

    SSL_set_bio(ssl_, readBio_, writeBio_); // SSL 接管 BIO 生命周期
    SSL_set_accept_state(ssl_);

    SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE);
}

SslConnection::~SslConnection()
{
    if (ssl_) SSL_free(ssl_);
}

void SslConnection::startHandshake()
{
    if (!ssl_) return;
    SSL_set_accept_state(ssl_);
    handleHandshake();
}

void SslConnection::flushWriteBio()
{
    if (!writeBio_) return;

    char out[4096];
    while (BIO_pending(writeBio_) > 0)
    {
        int n = BIO_read(writeBio_, out, sizeof(out));
        if (n > 0)
            conn_->send(out, n);
        else
            break;
    }
}

void SslConnection::handleHandshake()
{
    if (!ssl_ || state_ != SSLState::HANDSHAKE) return;

    int ret = SSL_do_handshake(ssl_);
    flushWriteBio(); // 非常关键：把握手产生的数据发出去

    if (ret == 1)
    {
        state_ = SSLState::ESTABLISHED;
        LOG_INFO << "SSL handshake completed successfully";
        LOG_INFO << "Using cipher: " << SSL_get_cipher(ssl_);
        LOG_INFO << "Protocol version: " << SSL_get_version(ssl_);
        return;
    }

    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    {
        // 等待更多网络数据或需要继续写（已 flush）
        return;
    }

    LOG_ERROR << "SSL handshake failed, ssl_error=" << err;
    logOpenSslErrors("handshake");
    state_ = SSLState::ERROR;
    conn_->shutdown();
}

void SslConnection::drainDecrypted()
{
    if (!ssl_ || state_ != SSLState::ESTABLISHED) return;

    char plain[4096];

    for (;;)
    {
        int n = SSL_read(ssl_, plain, sizeof(plain));
        if (n > 0)
        {
            decryptedBuffer_.append(plain, n);
            continue;
        }

        int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ)
        {
            // 目前没有更多明文可读
            break;
        }
        if (err == SSL_ERROR_ZERO_RETURN)
        {
            // 收到 close_notify
            conn_->shutdown();
            break;
        }

        LOG_ERROR << "SSL_read failed, ssl_error=" << err;
        logOpenSslErrors("SSL_read");
        state_ = SSLState::ERROR;
        conn_->shutdown();
        break;
    }
}

void SslConnection::onRead(const TcpConnectionPtr& conn, muduo::net::Buffer* buf,
                          muduo::Timestamp /*time*/)
{
    if (!ssl_ || state_ == SSLState::ERROR) return;

    // 1) 先把收到的密文写入 read BIO
    const char* data = buf->peek();
    size_t len = buf->readableBytes();
    if (len > 0)
    {
        int w = BIO_write(readBio_, data, static_cast<int>(len));
        if (w <= 0)
        {
            LOG_ERROR << "BIO_write failed";
            logOpenSslErrors("BIO_write");
            state_ = SSLState::ERROR;
            conn_->shutdown();
            return;
        }
        buf->retrieve(len); // 消费掉密文
    }

    // 2) 握手阶段推进握手
    if (state_ == SSLState::HANDSHAKE)
    {
        handleHandshake();
        if (state_ != SSLState::ESTABLISHED)
            return;
        // 握手刚完成可能已经有应用数据到来，继续往下解密
    }

    // 3) 已建立阶段，尽可能多地解密应用数据
    drainDecrypted();

    // 注意：解密出的数据保存在 decryptedBuffer_ 里，
    // 上层 HttpServer 会通过 getDecryptedBuffer() 来取并解析。
}

void SslConnection::send(const void* data, size_t len)
{
    if (!ssl_ || state_ != SSLState::ESTABLISHED)
    {
        LOG_ERROR << "Cannot send data before SSL handshake is complete";
        return;
    }

    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t left = len;

    while (left > 0)
    {
        int n = SSL_write(ssl_, p, static_cast<int>(left));
        flushWriteBio(); // 把 SSL_write 产生的密文发出去

        if (n > 0)
        {
            p += n;
            left -= n;
            continue;
        }

        int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        {
            // 非阻塞情况下可能出现，已 flush，等待下次可写再试（这里直接 break 也可）
            break;
        }

        LOG_ERROR << "SSL_write failed, ssl_error=" << err;
        logOpenSslErrors("SSL_write");
        state_ = SSLState::ERROR;
        conn_->shutdown();
        break;
    }
}

} // namespace ssl
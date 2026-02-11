#pragma once

#include "SslContext.h"

#include <muduo/base/noncopyable.h>
#include <muduo/base/Timestamp.h>
#include <muduo/net/Buffer.h>
#include <muduo/net/TcpConnection.h>

#include <openssl/ssl.h>

#include <memory>
#include <cstddef>

namespace ssl
{

class SslConnection : muduo::noncopyable
{
public:
    using TcpConnectionPtr = std::shared_ptr<muduo::net::TcpConnection>;

    explicit SslConnection(const TcpConnectionPtr& conn, SslContext* ctx);
    ~SslConnection();

    // 启动/推进握手（握手产生的数据会通过 flushWriteBio() 发到 TCP）
    void startHandshake();

    // 发送应用层明文数据：内部 SSL_write -> writeBio_ -> flush 到 TCP
    void send(const void* data, size_t len);

    // 收到网络密文数据（来自 TcpConnection 的 onMessage），喂给 readBio_，
    // 内部推进握手/解密，解密后的明文累积在 decryptedBuffer_ 中
    void onRead(const TcpConnectionPtr& conn,
                muduo::net::Buffer* buf,
                muduo::Timestamp receiveTime);

    bool isHandshakeCompleted() const { return state_ == SSLState::ESTABLISHED; }

    // 供上层（HttpServer）读取解密后的明文数据
    muduo::net::Buffer* getDecryptedBuffer() { return &decryptedBuffer_; }

private:
    // 将 writeBio_ 中待发送密文刷到 TCP（握手/SSL_write 后必须调用）
    void flushWriteBio();

    // 在 ESTABLISHED 状态下尽可能多地 SSL_read，把明文写入 decryptedBuffer_
    void drainDecrypted();

    // 推进握手状态机（会 flushWriteBio）
    void handleHandshake();

private:
    SSL*                ssl_{nullptr};      // OpenSSL SSL 连接
    SslContext*         ctx_{nullptr};      // SSL 上下文（不持有）
    TcpConnectionPtr    conn_;              // TCP 连接（持有共享指针）
    SSLState            state_{SSLState::HANDSHAKE};

    BIO*                readBio_{nullptr};  // 网络密文 -> SSL
    BIO*                writeBio_{nullptr}; // SSL -> 网络密文

    muduo::net::Buffer  decryptedBuffer_;   // 解密后的明文数据（给 HTTP 层解析）
};

} // namespace ssl

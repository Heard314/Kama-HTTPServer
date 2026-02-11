#pragma once
#include "SslConfig.h"

#include <muduo/base/noncopyable.h>
#include <openssl/ssl.h>

namespace ssl
{

class SslContext : muduo::noncopyable
{
public:
    explicit SslContext(const SslConfig& config);
    ~SslContext();

    bool initialize();
    SSL_CTX* getNativeHandle() const { return ctx_; }

private:
    bool loadCertificates();
    bool setupProtocolVersions();
    bool setupCiphers();
    void setupSessionCache();
    bool setupOptions();

    static void logErrorQueue(const char* msg);

private:
    SSL_CTX*  ctx_{nullptr};
    SslConfig config_;
};

} // namespace ssl

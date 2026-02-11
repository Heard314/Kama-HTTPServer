#include "../../include/ssl/SslContext.h"
#include <muduo/base/Logging.h>

#include <openssl/err.h>
#include <mutex>

namespace ssl
{

static int toOpenSslVersion(SSLVersion v)
{
    switch (v)
    {
        case SSLVersion::TLS_1_0: return TLS1_VERSION;
        case SSLVersion::TLS_1_1: return TLS1_1_VERSION;
        case SSLVersion::TLS_1_2: return TLS1_2_VERSION;
        case SSLVersion::TLS_1_3: return TLS1_3_VERSION;
        default: return TLS1_2_VERSION;
    }
}

void SslContext::logErrorQueue(const char* msg)
{
    unsigned long e = 0;
    bool any = false;
    while ((e = ERR_get_error()) != 0)
    {
        any = true;
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        LOG_ERROR << msg << ": " << buf;
    }
    if (!any)
    {
        LOG_ERROR << msg << ": (no OpenSSL error in queue)";
    }
}

SslContext::SslContext(const SslConfig& config)
    : config_(config)
{
}

SslContext::~SslContext()
{
    if (ctx_) SSL_CTX_free(ctx_);
}

bool SslContext::initialize()
{
    static std::once_flag once;
    std::call_once(once, [] {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    });

    ERR_clear_error();

    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_)
    {
        logErrorQueue("Failed to create SSL_CTX");
        return false;
    }

    // ✅ 不验证客户端证书（只做服务器证书）
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);

    if (!setupOptions()) return false;
    if (!setupProtocolVersions()) return false;
    if (!loadCertificates()) return false;
    if (!setupCiphers()) return false;

    setupSessionCache();

    LOG_INFO << "SSL context initialized successfully";
    return true;
}

bool SslContext::setupOptions()
{
    long options =
        SSL_OP_NO_SSLv2 |
        SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_CIPHER_SERVER_PREFERENCE;

#ifdef SSL_OP_NO_RENEGOTIATION
    options |= SSL_OP_NO_RENEGOTIATION;
#endif

    SSL_CTX_set_options(ctx_, options);

#if defined(SSL_CTX_set1_groups_list)
    // 推荐曲线组（可选）
    if (SSL_CTX_set1_groups_list(ctx_, "X25519:P-256:P-384") != 1)
    {
        logErrorQueue("Failed to set groups list");
        return false;
    }
#endif

    return true;
}

bool SslContext::setupProtocolVersions()
{
    const int minv = toOpenSslVersion(config_.getProtocolVersion());

    // ✅ 正确方式：设置允许的协议范围
    if (SSL_CTX_set_min_proto_version(ctx_, minv) != 1)
    {
        logErrorQueue("Failed to set min proto version");
        return false;
    }

    // 默认允许到 TLS1.3（OpenSSL 支持的话）
#ifdef TLS1_3_VERSION
    if (SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION) != 1)
    {
        logErrorQueue("Failed to set max proto version");
        return false;
    }
#else
    // 如果编译的 OpenSSL 没 TLS1.3，就允许到 TLS1.2
    if (SSL_CTX_set_max_proto_version(ctx_, TLS1_2_VERSION) != 1)
    {
        logErrorQueue("Failed to set max proto version (TLS1.2)");
        return false;
    }
#endif

    return true;
}

bool SslContext::loadCertificates()
{
    ERR_clear_error();

    // 推荐：如果提供 chainFile（fullchain.pem），优先用它
    if (!config_.getCertificateChainFile().empty())
    {
        if (SSL_CTX_use_certificate_chain_file(ctx_,
            config_.getCertificateChainFile().c_str()) <= 0)
        {
            logErrorQueue("Failed to load certificate chain file");
            return false;
        }
    }
    else
    {
        if (config_.getCertificateFile().empty())
        {
            LOG_ERROR << "Certificate file is empty";
            return false;
        }
        if (SSL_CTX_use_certificate_file(ctx_,
            config_.getCertificateFile().c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            logErrorQueue("Failed to load server certificate file");
            return false;
        }
    }

    if (config_.getPrivateKeyFile().empty())
    {
        LOG_ERROR << "Private key file is empty";
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx_,
        config_.getPrivateKeyFile().c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        logErrorQueue("Failed to load private key");
        return false;
    }

    if (SSL_CTX_check_private_key(ctx_) != 1)
    {
        logErrorQueue("Private key does not match certificate");
        return false;
    }

    return true;
}

bool SslContext::setupCiphers()
{
    ERR_clear_error();

    // TLS1.2 及以下
    if (!config_.getCipherList().empty())
    {
        if (SSL_CTX_set_cipher_list(ctx_, config_.getCipherList().c_str()) != 1)
        {
            logErrorQueue("Failed to set TLS1.2- cipher list");
            return false;
        }
    }

    // TLS1.3（OpenSSL 1.1.1+）
#if defined(SSL_CTX_set_ciphersuites)
    if (!config_.getTls13CipherSuites().empty())
    {
        if (SSL_CTX_set_ciphersuites(ctx_, config_.getTls13CipherSuites().c_str()) != 1)
        {
            logErrorQueue("Failed to set TLS1.3 cipher suites");
            return false;
        }
    }
#endif

    return true;
}

void SslContext::setupSessionCache()
{
    SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(ctx_, config_.getSessionCacheSize());
    SSL_CTX_set_timeout(ctx_, config_.getSessionTimeout());
}

} // namespace ssl

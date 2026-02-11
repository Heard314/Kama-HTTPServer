#pragma once
#include "SslTypes.h"
#include <string>

namespace ssl
{

class SslConfig
{
public:
    SslConfig();
    ~SslConfig() = default;

    // 证书配置
    void setCertificateFile(const std::string& certFile) { certFile_ = certFile; }
    void setPrivateKeyFile(const std::string& keyFile) { keyFile_ = keyFile; }

    // 推荐：fullchain.pem（服务端证书 + 中间证书链），没有就留空
    void setCertificateChainFile(const std::string& chainFile) { chainFile_ = chainFile; }

    // 把 version 当作“最小版本”（更符合实践）
    void setProtocolVersion(SSLVersion version) { minVersion_ = version; }

    // TLS1.2 及以下 cipher list
    void setCipherList(const std::string& cipherList) { cipherList_ = cipherList; }

    // TLS1.3 cipher suites（OpenSSL 1.1.1+）
    void setTls13CipherSuites(const std::string& suites) { tls13CipherSuites_ = suites; }

    // 会话配置
    void setSessionTimeout(int seconds) { sessionTimeout_ = seconds; }
    void setSessionCacheSize(long size) { sessionCacheSize_ = size; }

    // Getters
    const std::string& getCertificateFile() const { return certFile_; }
    const std::string& getPrivateKeyFile() const { return keyFile_; }
    const std::string& getCertificateChainFile() const { return chainFile_; }

    SSLVersion getProtocolVersion() const { return minVersion_; }
    const std::string& getCipherList() const { return cipherList_; }
    const std::string& getTls13CipherSuites() const { return tls13CipherSuites_; }

    int getSessionTimeout() const { return sessionTimeout_; }
    long getSessionCacheSize() const { return sessionCacheSize_; }

private:
    std::string certFile_;
    std::string keyFile_;
    std::string chainFile_;

    SSLVersion  minVersion_;
    std::string cipherList_;
    std::string tls13CipherSuites_;

    int         sessionTimeout_;
    long        sessionCacheSize_;
};

} // namespace ssl

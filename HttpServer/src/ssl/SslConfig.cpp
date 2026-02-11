#include "../../include/ssl/SslConfig.h"

namespace ssl
{

SslConfig::SslConfig()
    : minVersion_(SSLVersion::TLS_1_2)
    , cipherList_("HIGH:!aNULL:!MD5:!RC4:!3DES")
    , tls13CipherSuites_("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")
    , sessionTimeout_(300)
    , sessionCacheSize_(20480L)
{
}

} // namespace ssl

#include "../../include/ssl/SslConfig.h"

namespace ssl
{
SslConfig::SslConfig(
        std::string certFile,
        std::string keyFile,
        std::string chainFile)
    : version_(SSLVersion::TLS_1_2)
    , cipherList_("HIGH:!aNULL:!MDS")
    , verifyClient_(false)
    , verifyDepth_(4)
    , sessionTimeout_(300)
    , sessionCacheSize_(20480L)
{
    setCertificateFile(certFile);
    setCertificateChainFile(chainFile);
    setPrivateKeyFile(keyFile);
}
};
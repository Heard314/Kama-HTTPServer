#include "../../include/http/HttpServer.h"

#include <any>
#include <functional>
#include <memory>
#include <stdexcept>

namespace http
{

// 默认http回应函数
void defaultHttpCallback(const HttpRequest &, HttpResponse *resp)
{
    resp->setStatusCode(HttpResponse::k404NotFound);
    resp->setStatusMessage("Not Found");
    resp->setCloseConnection(true);
}

HttpServer::HttpServer(int port,
                       const std::string &name,
                       muduo::net::TcpServer::Option option,
                       bool useSSL,
                       std::optional<ssl::SslConfig> config)
    : listenAddr_(port)
    , server_(&mainLoop_, listenAddr_, name, option)
    , useSSL_(useSSL)
    , httpCallback_(std::bind(&HttpServer::requestHandler, this, std::placeholders::_1, std::placeholders::_2))
{
    if(useSSL)
    {
        sslInit(config.value());
        if(!config.has_value())
        {
            throw std::runtime_error("Enable ssl, but haven't provided the ssl config.");
        }
    }
    initialize();
}

// 服务器运行函数
void HttpServer::start()
{
    LOG_WARN << "HttpServer[" << server_.name() << "] starts listening on" << server_.ipPort();
    server_.start();
    mainLoop_.loop();
}

void HttpServer::initialize()
{
    // 设置回调函数
    server_.setConnectionCallback(
        std::bind(&HttpServer::onConnection, this, std::placeholders::_1));
//    server_.setMessageCallback(
//        std::bind(&HttpServer::onMessage, this,
//                  std::placeholders::_1,
//                  std::placeholders::_2,
//                  std::placeholders::_3));
}

void HttpServer::sslInit(const ssl::SslConfig& config)
{
    SSL_load_error_strings ();
    SSL_library_init ();
    OpenSSL_add_all_algorithms();
//#if OPENSSL_VERSION_MAJOR < 3
    ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
//#endif
//    ERR_load_crypto_strings();
    sslCtx_ = std::make_unique<ssl::SslContext>(config);
    if (!sslCtx_->initialize())
    {
        LOG_ERROR << "Failed to initialize SSL context";
        abort();
    }
}

void HttpServer::onConnection(const muduo::net::TcpConnectionPtr& conn)
{
    std::cout<<"Get a new http connection.\n";
    if (conn->connected())
    {
        conn->setContext(HttpContext());
        conn->setMessageCallback(
                std::bind(&HttpServer::onMessage, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

        //初始化写缓存
//        connsWriteBuffer[conn] = muduo::net::Buffer();
        if (useSSL_)
        {
            auto sslConn = std::make_shared<ssl::SslConnection>(conn, sslCtx_.get());
//            sslConn->setMessageCallback(
//                std::bind(&HttpServer::onSslMessage, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
            sslConns_[conn] = std::move(sslConn);
//            sslConns_[conn]->startHandshake();
//            sslConn->startHandshake();
            // 设置 conn 的 messageCallback，将数据传递给 SslConnection 处理
//            conn->setMessageCallback(
//                    [sslConn](const muduo::net::TcpConnectionPtr& tcpConn, muduo::net::Buffer* buf, muduo::Timestamp receiveTime) {
//                        sslConn->onRead(tcpConn, buf, receiveTime);
//                    });
        }
    }
    else 
    {
        // 连接断开处理
        if (useSSL_) {
//            auto contextPtr = boost::any_cast<std::shared_ptr<ssl::SslConnection>>(conn->getContext());
//            if (contextPtr) {
//                LOG_INFO << "SSL connection closed for " << conn->peerAddress().toIpPort();
                // SslConnection 对象是 std::shared_ptr，当 conn 的生命周期结束，
                // 并且没有其他 shared_ptr 指向它时，会自动销毁，
                // SslConnection 的析构函数会清理 OpenSSL 相关的资源 (SSL_shutdown, SSL_free)。
                // 你可能需要在这里做一些额外的清理工作，如果 SslConnection 持有其他需要显式释放的资源。
            }
        } else {
            LOG_INFO << "HTTP connection closed for " << conn->peerAddress().toIpPort();
            // 对于非 SSL 连接，HttpContext 是存储在 conn 的上下文中的值对象，
            // muduo 会自动处理其生命周期。你可能需要在这里做一些额外的清理工作，
            // 如果 HttpContext 或你的 HTTP 处理逻辑持有其他需要显式释放的资源。
        }
    }
}

//void HttpServer::onSslMessage(const muduo::net::TcpConnectionPtr &conn,
//                                   muduo::net::Buffer *buf,
//                                   muduo::Timestamp receiveTime) {
//    try {
//        HttpContext *context = boost::any_cast<HttpContext>(conn->getMutableContext());
//        if (!context->parseRequest(buf, receiveTime)) {
//            conn->send("HTTP/1.1 400 Bad Request\r\n\r\n");
//            conn->shutdown();
//            return;
//        }
//        if (context->gotAll()) {
//            httpHandler(conn, context->request());
//            context->reset();
//        }
//    } catch (const std::exception &e) {
//        LOG_ERROR << "Exception in processSslMessage: " << e.what();
//        conn->send("HTTP/1.1 400 Bad Request\r\n\r\n");
//        conn->shutdown();
//    }
//}

void HttpServer::onMessage(const muduo::net::TcpConnectionPtr &conn,
                           muduo::net::Buffer *buf,
                           muduo::Timestamp receiveTime)
{
    try
    {
        if (useSSL_)
        {
            LOG_INFO << "onMessage useSSL_ is true";
            // 1.查找对应的SSL连接
            auto it = sslConns_.find(conn);
            if (it != sslConns_.end())
            {
                auto sslConn = it->second;
                LOG_INFO << "onMessage sslConns_ is not empty";
                // 2. 将收到的消息放到SSL的rbio中
                // 3. 然后通过SSL_read把解密数据读出来
//                it->second->onRead(conn, buf, receiveTime);
                muduo::net::Buffer* decryptedBuf = sslConn->transferToBioAndRead(buf);
                // 3. 如果 SSL 握手还未完成，直接返回
//                if (!it->second->isHandshakeCompleted())
//                {
//                    LOG_INFO << "onMessage sslConns_ is not empty";
//                    return;
//                }
                if (decryptedBuf->readableBytes() == 0)
                    return; // 没有解密后的数据

                // 4. 使用解密后的数据进行HTTP 处理
                buf = decryptedBuf; // 将 buf 指向解密后的数据
                LOG_INFO << "onMessage decryptedBuf is not empty";
            }
        }
        // HttpContext对象用于解析出buf中的请求报文，并把报文的关键信息封装到HttpRequest对象中
        HttpContext *context = boost::any_cast<HttpContext>(conn->getMutableContext());
        if (!context->parseRequest(buf, receiveTime)) // 解析一个http请求
        {
            // 如果解析http报文过程中出错
            conn->send("HTTP/1.1 400 Bad Request\r\n\r\n");
            conn->shutdown();
        }
        // 如果buf缓冲区中解析出一个完整的数据包才封装响应报文
        if (context->gotAll())
        {
            httpHandler(conn, context->request());
            context->reset();
        }
    }
    catch (const std::exception &e)
    {
        // 捕获异常，返回错误信息
        LOG_ERROR << "Exception in onMessage: " << e.what();
        conn->send("HTTP/1.1 400 Bad Request\r\n\r\n");
        conn->shutdown();
    }
}

void HttpServer::httpHandler(const muduo::net::TcpConnectionPtr &conn, const HttpRequest &req)
{
    const std::string &connection = req.getHeader("Connection");
    bool close = ((connection == "close") ||
                  (req.getVersion() == "HTTP/1.0" && connection != "Keep-Alive"));
    HttpResponse response(close);

    // 根据请求报文信息来封装响应报文对象
    httpCallback_(req, &response); // 执行onHttpCallback函数

    // 可以给response设置一个成员，判断是否请求的是文件，如果是文件设置为true，并且存在文件位置在这里send出去。
    muduo::net::Buffer buf;
    response.appendToBuffer(&buf);
    // 打印完整的响应内容用于调试
    LOG_INFO << "Sending response:\n" << buf.toStringPiece().as_string();

    conn->send(&buf);
    // 如果是短连接的话，返回响应报文后就断开连接
    if (response.closeConnection())
    {
        conn->shutdown();
    }
}

// 处理请求的业务逻辑
void HttpServer::requestHandler(const HttpRequest &req, HttpResponse *resp)
{
    try
    {
        // 处理请求前的中间件
        HttpRequest mutableReq = req;
        middlewareChain_.processBefore(mutableReq);

        // 路由处理
        if (!router_.route(mutableReq, resp))
        {
            LOG_INFO << "请求的啥，url：" << req.method() << " " << req.path();
            LOG_INFO << "未找到路由，返回404";
            resp->setStatusCode(HttpResponse::k404NotFound);
            resp->setStatusMessage("Not Found");
            resp->setCloseConnection(true);
        }

        // 处理响应后的中间件
        middlewareChain_.processAfter(*resp);
    }
    catch (const HttpResponse& res) 
    {
        // 处理中间件抛出的响应（如CORS预检请求）
        *resp = res;
    }
    catch (const std::exception& e) 
    {
        // 错误处理
        resp->setStatusCode(HttpResponse::k500InternalServerError);
        resp->setBody(e.what());
    }
}

} // namespace http
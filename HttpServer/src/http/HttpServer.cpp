#include "../../include/http/HttpServer.h"

#include <any>
#include <functional>
#include <memory>

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
                       bool useSSL,
                       muduo::net::TcpServer::Option option)
    : listenAddr_(port)
    , server_(&mainLoop_, listenAddr_, name, option)
    , useSSL_(useSSL)
    , httpCallback_(std::bind(&HttpServer::handleRequest, this, std::placeholders::_1, std::placeholders::_2))
{
    initialize();
}

// 服务器运行函数
void HttpServer::start()
{
    LOG_WARN << "HttpServer[" << server_.name() << "] starts listening on" << server_.ipPort();
    if (useSSL_ && !sslCtx_)
    {
        LOG_ERROR << "SSL enabled but sslCtx_ not initialized. Call setSslConfig() before start().";
        abort();
    }
    server_.start();
    mainLoop_.loop();
}

void HttpServer::initialize()
{
    // 设置回调函数
    server_.setConnectionCallback(
        std::bind(&HttpServer::onConnection, this, std::placeholders::_1));
    server_.setMessageCallback(
        std::bind(&HttpServer::onMessage, this,
                  std::placeholders::_1,
                  std::placeholders::_2,
                  std::placeholders::_3));
}

void HttpServer::setSslConfig(const ssl::SslConfig& config)
{
    if (useSSL_)
    {
        sslCtx_ = std::make_unique<ssl::SslContext>(config);
        if (!sslCtx_->initialize())
        {
            LOG_ERROR << "Failed to initialize SSL context";
            abort();
        }
    }
}

void HttpServer::onConnection(const muduo::net::TcpConnectionPtr& conn)
{
    if (conn->connected())
    {
        conn->setContext(HttpContext());
        if (useSSL_)
        {
            if (!sslCtx_)
            {
                LOG_ERROR << "useSSL_ is true but sslCtx_ is null. Call setSslConfig() before start().";
                conn->shutdown();
                return;
            }
            auto sslConn = std::make_unique<ssl::SslConnection>(conn, sslCtx_.get());
            // sslConn->setMessageCallback(
            //     std::bind(&HttpServer::onMessage, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
            sslConns_[conn] = std::move(sslConn);
            sslConns_[conn]->startHandshake();
        }
    }
    else 
    {
        if (useSSL_)
        {
            sslConns_.erase(conn);
        }
    }
}

void HttpServer::onMessage(const muduo::net::TcpConnectionPtr &conn,
                           muduo::net::Buffer *buf,
                           muduo::Timestamp receiveTime)
{
    try
    {
        // 这层判断只是代表是否支持ssl
        if (useSSL_)
        {
            LOG_INFO << "onMessage useSSL_ is true";
            // 1.查找对应的SSL连接
            auto it = sslConns_.find(conn);
            if (it == sslConns_.end())
            {
                conn->shutdown();
                return;
            }
            LOG_INFO << "onMessage sslConns_ is not empty";
            // 2. SSL连接处理数据
            it->second->onRead(conn, buf, receiveTime);

            // 3. 如果 SSL 握手还未完成，直接返回
            if (!it->second->isHandshakeCompleted())
            {
                LOG_INFO << "onMessage sslConns_ is not empty";
                return;
            }

            // 4. 从SSL连接的解密缓冲区获取数据
            muduo::net::Buffer* decryptedBuf = it->second->getDecryptedBuffer();
            if (decryptedBuf->readableBytes() == 0)
                return; // 没有解密后的数据

            // 5. 使用解密后的数据进行HTTP 处理
            buf = decryptedBuf; // 将 buf 指向解密后的数据
            LOG_INFO << "onMessage decryptedBuf is not empty";
        
        }
        // HttpContext对象用于解析出buf中的请求报文，并把报文的关键信息封装到HttpRequest对象中
        HttpContext *context = boost::any_cast<HttpContext>(conn->getMutableContext());
        if (context == nullptr)
        {
            conn->send("HTTP/1.1 500 Internal Server Error\r\n\r\n");
            conn->shutdown();
            return;
        }
        
        // Support handling multiple complete requests within a single callback.
        while (buf->readableBytes() > 0)
        {
            if (!context->parseRequest(buf, receiveTime))
            {
                conn->send("HTTP/1.1 400 Bad Request\r\n\r\n");
                conn->shutdown();
                return;
            }

            if (context->gotAll())
            {
                onRequest(conn, context->request());
                context->reset();
                // 继续循环，看 buf 里是否还有下一个请求
            }
            else
            {
                // 还没凑够一个完整 HTTP 请求
                break;
            }
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

void HttpServer::onRequest(const muduo::net::TcpConnectionPtr &conn, const HttpRequest &req)
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

    auto piece = buf.toStringPiece();
    if (useSSL_)
    {
        auto it = sslConns_.find(conn);
        if (it == sslConns_.end() || !it->second->isHandshakeCompleted())
        {
            LOG_WARN << "SSL connection not ready, closing.";
            conn->shutdown();
            return;
        }
        it->second->send(piece.data(), piece.size());
    }
    else
    {
        conn->send(&buf);
    }
    // 如果是短连接的话，返回响应报文后就断开连接
    if (response.closeConnection())        
        conn->shutdown();
}

// 执行请求对应的路由处理函数
void HttpServer::handleRequest(const HttpRequest &req, HttpResponse *resp)
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
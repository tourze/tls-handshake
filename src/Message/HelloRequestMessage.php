<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS HelloRequest消息
 * 
 * 参考RFC 5246 (TLS 1.2) - 仅在TLS 1.2中使用
 * HelloRequest是服务器可以发送的一个简单通知，请求客户端重新开始协商过程。
 */
class HelloRequestMessage extends AbstractHandshakeMessage
{
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = HandshakeMessageType::HELLO_REQUEST;
    }
    
    /**
     * 将消息序列化为二进制数据
     * 
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        // HelloRequest消息没有内容
        return '';
    }
    
    /**
     * 从二进制数据反序列化消息
     * 
     * @param string $data 二进制数据
     * @return static 解析后的消息对象
     */
    public static function decode(string $data): static
    {
        // HelloRequest消息没有内容，直接返回新的实例
        return new static();
    }
    
    /**
     * 验证消息是否有效
     * 
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // HelloRequest消息总是有效的
        return true;
    }
} 
<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS Finished消息
 * 
 * 参考RFC 5246 (TLS 1.2) 和 RFC 8446 (TLS 1.3)
 */
class FinishedMessage extends AbstractHandshakeMessage
{
    /**
     * 验证数据
     * 
     * @var string
     */
    private string $verifyData = '';
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = HandshakeMessageType::FINISHED;
    }
    
    /**
     * 获取验证数据
     * 
     * @return string 验证数据
     */
    public function getVerifyData(): string
    {
        return $this->verifyData;
    }
    
    /**
     * 设置验证数据
     * 
     * @param string $verifyData 验证数据
     * @return self
     */
    public function setVerifyData(string $verifyData): self
    {
        $this->verifyData = $verifyData;
        return $this;
    }
    
    /**
     * 将消息序列化为二进制数据
     * 
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        // Finished消息直接包含验证数据
        return $this->verifyData;
    }
    
    /**
     * 从二进制数据反序列化消息
     * 
     * @param string $data 二进制数据
     * @return static 解析后的消息对象
     */
    public static function decode(string $data): static
    {
        $message = new static();
        
        // Finished消息的所有数据都是验证数据
        $message->setVerifyData($data);
        
        return $message;
    }
    
    /**
     * 验证消息是否有效
     * 
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // 必须有验证数据
        return !empty($this->verifyData);
    }
}

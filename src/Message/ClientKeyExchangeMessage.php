<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS ClientKeyExchange消息
 * 
 * 参考RFC 5246 (TLS 1.2) - 仅在TLS 1.2中使用
 */
class ClientKeyExchangeMessage extends AbstractHandshakeMessage
{
    /**
     * 加密的预主密钥
     * 
     * @var string
     */
    private string $encryptedPreMasterSecret = '';
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = HandshakeMessageType::CLIENT_KEY_EXCHANGE;
    }
    
    /**
     * 获取加密的预主密钥
     * 
     * @return string 加密的预主密钥
     */
    public function getEncryptedPreMasterSecret(): string
    {
        return $this->encryptedPreMasterSecret;
    }
    
    /**
     * 设置加密的预主密钥
     * 
     * @param string $encryptedPreMasterSecret 加密的预主密钥
     * @return self
     */
    public function setEncryptedPreMasterSecret(string $encryptedPreMasterSecret): self
    {
        $this->encryptedPreMasterSecret = $encryptedPreMasterSecret;
        return $this;
    }
    
    /**
     * 将消息序列化为二进制数据
     * 
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        // 预主密钥长度（2字节）
        $result = $this->encodeUint16(strlen($this->encryptedPreMasterSecret));
        
        // 预主密钥数据
        $result .= $this->encryptedPreMasterSecret;
        
        return $result;
    }
    
    /**
     * 从二进制数据反序列化消息
     * 
     * @param string $data 二进制数据
     * @return static 解析后的消息对象
     * @throws \InvalidArgumentException 如果数据格式无效
     */
    public static function decode(string $data): static
    {
        $message = new static();
        $offset = 0;
        
        // 检查数据长度
        if (strlen($data) < 2) { // 至少需要2字节的预主密钥长度
            throw new \InvalidArgumentException('ClientKeyExchange message too short');
        }
        
        // 预主密钥长度
        $secretLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 检查数据长度是否足够
        if ($offset + $secretLength > strlen($data)) {
            throw new \InvalidArgumentException('ClientKeyExchange message pre-master secret length mismatch');
        }
        
        // 预主密钥数据
        $message->setEncryptedPreMasterSecret(substr($data, $offset, $secretLength));
        
        return $message;
    }
    
    /**
     * 验证消息是否有效
     * 
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // 必须有加密的预主密钥
        return !empty($this->encryptedPreMasterSecret);
    }
}

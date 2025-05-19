<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS CertificateVerify消息
 * 
 * 参考RFC 5246 (TLS 1.2) 和 RFC 8446 (TLS 1.3)
 */
class CertificateVerifyMessage extends AbstractHandshakeMessage
{
    /**
     * 签名算法
     * 
     * @var int
     */
    private int $signatureAlgorithm = 0;
    
    /**
     * 签名数据
     * 
     * @var string
     */
    private string $signature = '';
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = HandshakeMessageType::CERTIFICATE_VERIFY;
    }
    
    /**
     * 获取签名算法
     * 
     * @return int 签名算法
     */
    public function getSignatureAlgorithm(): int
    {
        return $this->signatureAlgorithm;
    }
    
    /**
     * 设置签名算法
     * 
     * @param int $signatureAlgorithm 签名算法
     * @return self
     */
    public function setSignatureAlgorithm(int $signatureAlgorithm): self
    {
        $this->signatureAlgorithm = $signatureAlgorithm;
        return $this;
    }
    
    /**
     * 获取签名数据
     * 
     * @return string 签名数据
     */
    public function getSignature(): string
    {
        return $this->signature;
    }
    
    /**
     * 设置签名数据
     * 
     * @param string $signature 签名数据
     * @return self
     */
    public function setSignature(string $signature): self
    {
        $this->signature = $signature;
        return $this;
    }
    
    /**
     * 将消息序列化为二进制数据
     * 
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        // 签名算法
        $result = $this->encodeUint16($this->signatureAlgorithm);
        
        // 签名长度和数据
        $result .= $this->encodeUint16(strlen($this->signature));
        $result .= $this->signature;
        
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
        if (strlen($data) < 4) { // 最小长度: 签名算法(2) + 签名长度(2)
            throw new \InvalidArgumentException('CertificateVerify message too short');
        }
        
        // 签名算法
        $message->setSignatureAlgorithm(self::decodeUint16($data, $offset));
        $offset += 2;
        
        // 签名长度
        $signatureLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 检查数据长度是否足够
        if ($offset + $signatureLength > strlen($data)) {
            throw new \InvalidArgumentException('CertificateVerify message signature length mismatch');
        }
        
        // 签名数据
        $message->setSignature(substr($data, $offset, $signatureLength));
        
        return $message;
    }
    
    /**
     * 验证消息是否有效
     * 
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // 必须有签名数据
        return !empty($this->signature);
    }
} 
<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS ClientHello消息
 * 
 * 参考RFC 5246 (TLS 1.2) 和 RFC 8446 (TLS 1.3)
 */
class ClientHelloMessage extends AbstractHandshakeMessage
{
    /**
     * TLS版本
     * 
     * @var int
     */
    private int $version = 0x0303; // TLS 1.2
    
    /**
     * 随机数 (32字节)
     * 
     * @var string
     */
    private string $random;
    
    /**
     * 会话ID
     * 
     * @var string
     */
    private string $sessionId = '';
    
    /**
     * 密码套件列表
     * 
     * @var array
     */
    private array $cipherSuites;
    
    /**
     * 压缩方法列表
     * 
     * @var array
     */
    private array $compressionMethods = [0]; // 默认只有null压缩方法
    
    /**
     * 扩展列表
     * 
     * @var array<int, string>
     */
    private array $extensions = [];
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = HandshakeMessageType::CLIENT_HELLO;
        
        // 生成随机数
        $this->random = random_bytes(32);
        
        // 设置默认密码套件 (TLS 1.2 和 TLS 1.3 通用的一些安全套件)
        $this->cipherSuites = [
            0x1301, // TLS_AES_128_GCM_SHA256 (TLS 1.3)
            0x1302, // TLS_AES_256_GCM_SHA384 (TLS 1.3)
            0x1303, // TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (TLS 1.2)
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (TLS 1.2)
        ];
    }
    
    /**
     * 获取TLS版本
     * 
     * @return int
     */
    public function getVersion(): int
    {
        return $this->version;
    }
    
    /**
     * 设置TLS版本
     * 
     * @param int $version TLS版本
     * @return self
     */
    public function setVersion(int $version): self
    {
        $this->version = $version;
        return $this;
    }
    
    /**
     * 获取随机数
     * 
     * @return string
     */
    public function getRandom(): string
    {
        return $this->random;
    }
    
    /**
     * 设置随机数
     * 
     * @param string $random 32字节随机数
     * @return self
     * @throws \InvalidArgumentException 如果随机数长度不是32字节
     */
    public function setRandom(string $random): self
    {
        if (strlen($random) !== 32) {
            throw new \InvalidArgumentException('Random data must be exactly 32 bytes');
        }
        
        $this->random = $random;
        return $this;
    }
    
    /**
     * 获取会话ID
     * 
     * @return string
     */
    public function getSessionId(): string
    {
        return $this->sessionId;
    }
    
    /**
     * 设置会话ID
     * 
     * @param string $sessionId 会话ID (最多32字节)
     * @return self
     * @throws \InvalidArgumentException 如果会话ID长度超过32字节
     */
    public function setSessionId(string $sessionId): self
    {
        if (strlen($sessionId) > 32) {
            throw new \InvalidArgumentException('Session ID cannot exceed 32 bytes');
        }
        
        $this->sessionId = $sessionId;
        return $this;
    }
    
    /**
     * 获取密码套件列表
     * 
     * @return array
     */
    public function getCipherSuites(): array
    {
        return $this->cipherSuites;
    }
    
    /**
     * 设置密码套件列表
     * 
     * @param array $cipherSuites 密码套件列表
     * @return self
     */
    public function setCipherSuites(array $cipherSuites): self
    {
        $this->cipherSuites = $cipherSuites;
        return $this;
    }
    
    /**
     * 获取压缩方法列表
     * 
     * @return array
     */
    public function getCompressionMethods(): array
    {
        return $this->compressionMethods;
    }
    
    /**
     * 设置压缩方法列表
     * 
     * @param array $compressionMethods 压缩方法列表
     * @return self
     */
    public function setCompressionMethods(array $compressionMethods): self
    {
        $this->compressionMethods = $compressionMethods;
        return $this;
    }
    
    /**
     * 获取扩展列表
     * 
     * @return array<int, string>
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }
    
    /**
     * 设置扩展列表
     * 
     * @param array<int, string> $extensions 扩展列表
     * @return self
     */
    public function setExtensions(array $extensions): self
    {
        $this->extensions = $extensions;
        return $this;
    }
    
    /**
     * 添加扩展
     * 
     * @param int $type 扩展类型
     * @param string $data 扩展数据
     * @return self
     */
    public function addExtension(int $type, string $data): self
    {
        $this->extensions[$type] = $data;
        return $this;
    }
    
    /**
     * 将消息序列化为二进制数据
     * 
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        // ClientVersion
        $result = $this->encodeUint16($this->version);
        
        // Random
        $result .= $this->random;
        
        // SessionID
        $sessionIdLength = strlen($this->sessionId);
        $result .= $this->encodeUint8($sessionIdLength);
        if ($sessionIdLength > 0) {
            $result .= $this->sessionId;
        }
        
        // CipherSuites
        $cipherSuitesLength = count($this->cipherSuites) * 2; // 每个套件2字节
        $result .= $this->encodeUint16($cipherSuitesLength);
        foreach ($this->cipherSuites as $suite) {
            $result .= $this->encodeUint16($suite);
        }
        
        // CompressionMethods
        $compressionMethodsLength = count($this->compressionMethods);
        $result .= $this->encodeUint8($compressionMethodsLength);
        foreach ($this->compressionMethods as $method) {
            $result .= $this->encodeUint8($method);
        }
        
        // Extensions
        if (!empty($this->extensions)) {
            $extensionsData = '';
            foreach ($this->extensions as $type => $data) {
                $extensionsData .= $this->encodeUint16($type);
                $extensionsData .= $this->encodeUint16(strlen($data));
                $extensionsData .= $data;
            }
            
            $result .= $this->encodeUint16(strlen($extensionsData));
            $result .= $extensionsData;
        }
        
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
        if (strlen($data) < 38) { // 最小长度: 版本(2) + 随机数(32) + 会话ID长度(1) + 密码套件长度(2) + 压缩方法长度(1)
            throw new \InvalidArgumentException('ClientHello message too short');
        }
        
        // ClientVersion
        $message->setVersion(self::decodeUint16($data, $offset));
        $offset += 2;
        
        // Random
        $message->setRandom(substr($data, $offset, 32));
        $offset += 32;
        
        // SessionID
        $sessionIdLength = self::decodeUint8($data, $offset);
        $offset += 1;
        if ($sessionIdLength > 0) {
            $message->setSessionId(substr($data, $offset, $sessionIdLength));
            $offset += $sessionIdLength;
        }
        
        // CipherSuites
        $cipherSuitesLength = self::decodeUint16($data, $offset);
        $offset += 2;
        if ($cipherSuitesLength % 2 !== 0) {
            throw new \InvalidArgumentException('Invalid cipher suites length');
        }
        
        $cipherSuites = [];
        for ($i = 0; $i < $cipherSuitesLength; $i += 2) {
            $cipherSuites[] = self::decodeUint16($data, $offset);
            $offset += 2;
        }
        $message->setCipherSuites($cipherSuites);
        
        // CompressionMethods
        $compressionMethodsLength = self::decodeUint8($data, $offset);
        $offset += 1;
        
        $compressionMethods = [];
        for ($i = 0; $i < $compressionMethodsLength; $i++) {
            $compressionMethods[] = self::decodeUint8($data, $offset);
            $offset += 1;
        }
        $message->setCompressionMethods($compressionMethods);
        
        // Extensions
        if ($offset < strlen($data)) {
            $extensionsLength = self::decodeUint16($data, $offset);
            $offset += 2;
            $extensionsEnd = $offset + $extensionsLength;
            
            while ($offset < $extensionsEnd) {
                $extensionType = self::decodeUint16($data, $offset);
                $offset += 2;
                
                $extensionLength = self::decodeUint16($data, $offset);
                $offset += 2;
                
                $extensionData = substr($data, $offset, $extensionLength);
                $offset += $extensionLength;
                
                $message->addExtension($extensionType, $extensionData);
            }
        }
        
        return $message;
    }
    
    /**
     * 验证消息是否有效
     * 
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // 必须有至少一个密码套件
        if (empty($this->cipherSuites)) {
            return false;
        }
        
        // 必须有随机数，长度为32字节
        if (strlen($this->random) !== 32) {
            return false;
        }
        
        // 会话ID长度不能超过32字节
        if (strlen($this->sessionId) > 32) {
            return false;
        }
        
        // 至少要有一个压缩方法
        if (empty($this->compressionMethods)) {
            return false;
        }
        
        return true;
    }
}

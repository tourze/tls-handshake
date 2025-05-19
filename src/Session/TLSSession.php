<?php

namespace Tourze\TLSHandshake\Session;

/**
 * TLS会话基本实现
 */
class TLSSession implements SessionInterface
{
    /**
     * 会话ID
     * 
     * @var string
     */
    private string $sessionId;
    
    /**
     * 加密套件
     * 
     * @var string
     */
    private string $cipherSuite;
    
    /**
     * TLS版本
     * 
     * @var int
     */
    private int $tlsVersion;
    
    /**
     * 主密钥
     * 
     * @var string
     */
    private string $masterSecret;
    
    /**
     * 创建时间
     * 
     * @var int
     */
    private int $creationTime;
    
    /**
     * 会话有效期（秒）
     * 
     * @var int
     */
    private int $lifetime = 3600; // 默认1小时
    
    /**
     * 构造函数
     * 
     * @param string $sessionId 会话ID
     * @param string $masterSecret 主密钥
     * @param string $cipherSuite 加密套件
     * @param int $tlsVersion TLS版本
     * @param int $timestamp 创建时间戳
     */
    public function __construct(
        string $sessionId = '',
        string $masterSecret = '',
        string $cipherSuite = '',
        int $tlsVersion = 0,
        int $timestamp = 0
    ) {
        $this->sessionId = $sessionId;
        $this->masterSecret = $masterSecret;
        $this->cipherSuite = $cipherSuite;
        $this->tlsVersion = $tlsVersion;
        $this->creationTime = $timestamp ?: time();
    }
    
    /**
     * {@inheritdoc}
     */
    public function getSessionId(): string
    {
        return $this->sessionId;
    }
    
    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function getCipherSuite(): string
    {
        return $this->cipherSuite;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setCipherSuite(string $cipherSuite): self
    {
        $this->cipherSuite = $cipherSuite;
        return $this;
    }
    
    /**
     * 获取TLS版本
     */
    public function getTlsVersion(): int
    {
        return $this->tlsVersion;
    }
    
    /**
     * 设置TLS版本
     */
    public function setTlsVersion(int $tlsVersion): self
    {
        $this->tlsVersion = $tlsVersion;
        return $this;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getMasterSecret(): string
    {
        return $this->masterSecret;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setMasterSecret(string $masterSecret): self
    {
        $this->masterSecret = $masterSecret;
        return $this;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getCreationTime(): int
    {
        return $this->creationTime;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setCreationTime(int $creationTime): self
    {
        $this->creationTime = $creationTime;
        return $this;
    }
    
    /**
     * 获取会话有效期
     * 
     * @return int 有效期（秒）
     */
    public function getLifetime(): int
    {
        return $this->lifetime;
    }
    
    /**
     * 设置会话有效期
     * 
     * @param int $lifetime 有效期（秒）
     * @return self
     */
    public function setLifetime(int $lifetime): self
    {
        $this->lifetime = $lifetime;
        return $this;
    }
    
    /**
     * 获取时间戳
     */
    public function getTimestamp(): int
    {
        return $this->creationTime;
    }
    
    /**
     * {@inheritdoc}
     */
    public function isValid(int $currentTime = 0): bool
    {
        $currentTime = $currentTime ?: time();
        return $currentTime < ($this->creationTime + $this->lifetime);
    }
} 
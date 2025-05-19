<?php

namespace Tourze\TLSHandshake\Session;

/**
 * TLS 1.3 PSK会话实现
 * 
 * 支持TLS 1.3的PSK会话恢复
 */
class TLS13PSKSession extends TLSSession
{
    /**
     * PSK身份
     * 
     * @var string
     */
    private string $pskIdentity;
    
    /**
     * 票据年龄添加值
     * 
     * @var int
     */
    private int $ticketAgeAdd;
    
    /**
     * 票据随机数
     * 
     * @var string
     */
    private string $ticketNonce;
    
    /**
     * 恢复主密钥
     * 
     * @var string
     */
    private string $resumptionMasterSecret;
    
    /**
     * 早期数据支持
     * 
     * @var bool
     */
    private bool $allowEarlyData = false;
    
    /**
     * 早期数据最大大小
     * 
     * @var int
     */
    private int $maxEarlyDataSize = 0;
    
    /**
     * 预共享密钥
     * 
     * @var string
     */
    private string $presharedKey;
    
    /**
     * 构造函数
     * 
     * @param string $sessionId 会话ID
     * @param int|string $cipherSuite 加密套件
     * @param string $masterSecret 主密钥
     * @param int $timestamp 创建时间戳
     * @param string $pskIdentity PSK身份
     * @param int $ticketAgeAdd 票据年龄添加值
     * @param string $ticketNonce 票据随机数
     * @param string $resumptionMasterSecret 恢复主密钥
     */
    public function __construct(
        string $sessionId = '',
        $cipherSuite = '',
        string $masterSecret = '',
        int $timestamp = 0,
        string $pskIdentity = '',
        int $ticketAgeAdd = 0,
        string $ticketNonce = '',
        string $resumptionMasterSecret = ''
    ) {
        // 转换cipherSuite类型以兼容测试
        $cipherSuiteStr = is_int($cipherSuite) ? dechex($cipherSuite) : $cipherSuite;
        
        parent::__construct(
            sessionId: $sessionId,
            masterSecret: $masterSecret,
            cipherSuite: $cipherSuiteStr,
            tlsVersion: 0x0304, // TLS 1.3
            timestamp: $timestamp
        );
        
        $this->pskIdentity = $pskIdentity;
        $this->presharedKey = $masterSecret; // 使用masterSecret作为presharedKey
        $this->ticketAgeAdd = $ticketAgeAdd;
        $this->ticketNonce = $ticketNonce;
        $this->resumptionMasterSecret = $resumptionMasterSecret;
    }
    
    /**
     * 获取PSK身份
     * 
     * @return string PSK身份
     */
    public function getPskIdentity(): string
    {
        return $this->pskIdentity;
    }
    
    /**
     * 设置PSK身份
     * 
     * @param string $pskIdentity PSK身份
     * @return self
     */
    public function setPskIdentity(string $pskIdentity): self
    {
        $this->pskIdentity = $pskIdentity;
        return $this;
    }
    
    /**
     * 获取票据年龄添加值
     * 
     * @return int 票据年龄添加值
     */
    public function getTicketAgeAdd(): int
    {
        return $this->ticketAgeAdd;
    }
    
    /**
     * 设置票据年龄添加值
     * 
     * @param int $ticketAgeAdd 票据年龄添加值
     * @return self
     */
    public function setTicketAgeAdd(int $ticketAgeAdd): self
    {
        $this->ticketAgeAdd = $ticketAgeAdd;
        return $this;
    }
    
    /**
     * 获取票据随机数
     * 
     * @return string 票据随机数
     */
    public function getTicketNonce(): string
    {
        return $this->ticketNonce;
    }
    
    /**
     * 设置票据随机数
     * 
     * @param string $ticketNonce 票据随机数
     * @return self
     */
    public function setTicketNonce(string $ticketNonce): self
    {
        $this->ticketNonce = $ticketNonce;
        return $this;
    }
    
    /**
     * 获取恢复主密钥
     * 
     * @return string 恢复主密钥
     */
    public function getResumptionMasterSecret(): string
    {
        return $this->resumptionMasterSecret;
    }
    
    /**
     * 设置恢复主密钥
     * 
     * @param string $resumptionMasterSecret 恢复主密钥
     * @return self
     */
    public function setResumptionMasterSecret(string $resumptionMasterSecret): self
    {
        $this->resumptionMasterSecret = $resumptionMasterSecret;
        return $this;
    }
    
    /**
     * 获取是否支持早期数据
     * 
     * @return bool 是否支持
     */
    public function isEarlyDataAllowed(): bool
    {
        return $this->allowEarlyData;
    }
    
    /**
     * 设置是否支持早期数据
     * 
     * @param bool $allowEarlyData 是否支持
     * @return self
     */
    public function setEarlyDataAllowed(bool $allowEarlyData): self
    {
        $this->allowEarlyData = $allowEarlyData;
        return $this;
    }
    
    /**
     * 获取早期数据最大大小
     * 
     * @return int 最大大小
     */
    public function getMaxEarlyDataSize(): int
    {
        return $this->maxEarlyDataSize;
    }
    
    /**
     * 设置早期数据最大大小
     * 
     * @param int $maxEarlyDataSize 最大大小
     * @return self
     */
    public function setMaxEarlyDataSize(int $maxEarlyDataSize): self
    {
        $this->maxEarlyDataSize = $maxEarlyDataSize;
        $this->allowEarlyData = ($maxEarlyDataSize > 0);
        return $this;
    }
    
    /**
     * 获取预共享密钥
     */
    public function getPresharedKey(): string
    {
        return $this->presharedKey;
    }
    
    /**
     * 设置预共享密钥
     */
    public function setPresharedKey(string $presharedKey): self
    {
        $this->presharedKey = $presharedKey;
        return $this;
    }
    
    /**
     * 计算客户端票据年龄
     * 
     * @param int $currentTime 当前时间
     * @return int 混淆后的票据年龄（毫秒）
     */
    public function getObfuscatedTicketAge(int $currentTime = 0): int
    {
        $currentTime = $currentTime ?: time();
        
        // 计算票据年龄（毫秒）
        $ticketAge = ($currentTime - $this->getCreationTime()) * 1000;
        
        // 应用混淆
        return ($ticketAge + $this->ticketAgeAdd) % (1 << 32);
    }
} 
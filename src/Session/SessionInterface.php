<?php

namespace Tourze\TLSHandshake\Session;

/**
 * TLS会话接口
 * 
 * 定义TLS会话的基本操作，用于会话恢复功能
 */
interface SessionInterface
{
    /**
     * 获取会话ID
     * 
     * @return string 会话ID
     */
    public function getSessionId(): string;
    
    /**
     * 设置会话ID
     * 
     * @param string $sessionId 会话ID
     * @return self
     */
    public function setSessionId(string $sessionId): self;
    
    /**
     * 获取会话加密套件
     * 
     * @return string 加密套件
     */
    public function getCipherSuite(): string;
    
    /**
     * 设置会话加密套件
     * 
     * @param string $cipherSuite 加密套件
     * @return self
     */
    public function setCipherSuite(string $cipherSuite): self;
    
    /**
     * 获取会话主密钥
     * 
     * @return string 主密钥
     */
    public function getMasterSecret(): string;
    
    /**
     * 设置会话主密钥
     * 
     * @param string $masterSecret 主密钥
     * @return self
     */
    public function setMasterSecret(string $masterSecret): self;
    
    /**
     * 获取会话创建时间
     * 
     * @return int 创建时间戳
     */
    public function getCreationTime(): int;
    
    /**
     * 设置会话创建时间
     * 
     * @param int $creationTime 创建时间戳
     * @return self
     */
    public function setCreationTime(int $creationTime): self;
    
    /**
     * 检查会话是否有效
     * 
     * @param int $currentTime 当前时间戳
     * @return bool 是否有效
     */
    public function isValid(int $currentTime = 0): bool;
} 
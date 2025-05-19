<?php

namespace Tourze\TLSHandshake\Session;

/**
 * PSK处理器
 * 
 * 负责管理预共享密钥及其关联的身份和会话
 */
class PSKHandler
{
    /**
     * PSK映射
     *
     * @var array<string, string> 身份映射到密钥
     */
    private array $pskMap = [];
    
    /**
     * 会话绑定
     *
     * @var array<string, TLS13PSKSession> 身份映射到会话
     */
    private array $sessionBindings = [];
    
    /**
     * 注册PSK
     *
     * @param string $identity PSK标识
     * @param string $key 预共享密钥
     * @return self
     */
    public function registerPSK(string $identity, string $key): self
    {
        $this->pskMap[$identity] = $key;
        return $this;
    }
    
    /**
     * 获取PSK
     *
     * @param string $identity PSK标识
     * @return string|null 预共享密钥，不存在则返回null
     */
    public function getPSK(string $identity): ?string
    {
        return $this->pskMap[$identity] ?? null;
    }
    
    /**
     * 检查是否存在指定标识的PSK
     *
     * @param string $identity PSK标识
     * @return bool 是否存在
     */
    public function hasPSK(string $identity): bool
    {
        return isset($this->pskMap[$identity]);
    }
    
    /**
     * 移除PSK
     *
     * @param string $identity PSK标识
     * @return bool 是否成功移除
     */
    public function removePSK(string $identity): bool
    {
        if (isset($this->pskMap[$identity])) {
            unset($this->pskMap[$identity]);
            
            // 同时移除相关联的会话绑定
            if (isset($this->sessionBindings[$identity])) {
                unset($this->sessionBindings[$identity]);
            }
            
            return true;
        }
        
        return false;
    }
    
    /**
     * 绑定会话到PSK
     *
     * @param string $identity PSK标识
     * @param TLS13PSKSession $session 会话对象
     * @return bool 是否成功绑定
     */
    public function bindSessionToPSK(string $identity, TLS13PSKSession $session): bool
    {
        if (!$this->hasPSK($identity)) {
            return false;
        }
        
        $this->sessionBindings[$identity] = $session;
        return true;
    }
    
    /**
     * 通过PSK获取绑定的会话
     *
     * @param string $identity PSK标识
     * @return TLS13PSKSession|null 会话对象，如果未绑定则返回null
     */
    public function getSessionByPSK(string $identity): ?TLS13PSKSession
    {
        return $this->sessionBindings[$identity] ?? null;
    }
}

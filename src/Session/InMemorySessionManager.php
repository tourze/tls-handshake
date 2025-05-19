<?php

namespace Tourze\TLSHandshake\Session;

/**
 * TLS内存会话管理器
 * 
 * 将会话存储在内存中，仅适用于单进程服务器
 */
class InMemorySessionManager implements SessionManagerInterface
{
    /**
     * 会话存储
     * 
     * @var array<string, SessionInterface>
     */
    private array $sessions = [];
    
    /**
     * {@inheritdoc}
     */
    public function createSession(string $cipherSuite, string $masterSecret): SessionInterface
    {
        $session = new TLSSession(
            sessionId: bin2hex(random_bytes(16)), // 生成32个字符的随机会话ID
            masterSecret: $masterSecret,
            cipherSuite: $cipherSuite,
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );
        
        $this->storeSession($session);
        
        return $session;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getSessionById(string $sessionId): ?SessionInterface
    {
        if (!isset($this->sessions[$sessionId])) {
            return null;
        }
        
        $session = $this->sessions[$sessionId];
        
        // 检查会话是否有效
        if (!$session->isValid()) {
            $this->removeSession($sessionId);
            return null;
        }
        
        return $session;
    }
    
    /**
     * {@inheritdoc}
     */
    public function storeSession(SessionInterface $session): bool
    {
        $this->sessions[$session->getSessionId()] = $session;
        return true;
    }
    
    /**
     * {@inheritdoc}
     */
    public function removeSession(string $sessionId): bool
    {
        if (isset($this->sessions[$sessionId])) {
            unset($this->sessions[$sessionId]);
            return true;
        }
        
        return false;
    }
    
    /**
     * {@inheritdoc}
     */
    public function cleanExpiredSessions(): int
    {
        $count = 0;
        $currentTime = time();
        
        foreach ($this->sessions as $sessionId => $session) {
            if (!$session->isValid($currentTime)) {
                unset($this->sessions[$sessionId]);
                $count++;
            }
        }
        
        return $count;
    }
} 
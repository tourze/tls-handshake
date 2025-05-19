<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Session\SessionIdManager;
use Tourze\TLSHandshake\Session\TLSSession;

class SessionIdManagerTest extends TestCase
{
    private SessionIdManager $sessionIdManager;

    protected function setUp(): void
    {
        $this->sessionIdManager = new SessionIdManager();
    }

    public function testCanStoreAndRetrieveSession(): void
    {
        // 创建一个测试会话
        $sessionId = random_bytes(32);
        $session = new TLSSession(
            sessionId: $sessionId,
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 存储会话
        $this->sessionIdManager->storeSession($session);

        // 验证能够通过会话ID检索会话
        $retrievedSession = $this->sessionIdManager->getSession($sessionId);
        
        $this->assertNotNull($retrievedSession);
        $this->assertSame($session->getSessionId(), $retrievedSession->getSessionId());
        $this->assertSame($session->getMasterSecret(), $retrievedSession->getMasterSecret());
        $this->assertSame($session->getCipherSuite(), $retrievedSession->getCipherSuite());
        $this->assertSame($session->getTlsVersion(), $retrievedSession->getTlsVersion());
    }

    public function testNonExistentSessionReturnsNull(): void
    {
        $nonExistentSessionId = random_bytes(32);
        
        $this->assertNull($this->sessionIdManager->getSession($nonExistentSessionId));
    }

    public function testCanRemoveSession(): void
    {
        // 创建一个测试会话
        $sessionId = random_bytes(32);
        $session = new TLSSession(
            sessionId: $sessionId,
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 存储会话
        $this->sessionIdManager->storeSession($session);
        
        // 验证会话存在
        $this->assertNotNull($this->sessionIdManager->getSession($sessionId));
        
        // 移除会话
        $this->sessionIdManager->removeSession($sessionId);
        
        // 验证会话已被移除
        $this->assertNull($this->sessionIdManager->getSession($sessionId));
    }

    public function testCanClearAllSessions(): void
    {
        // 创建多个测试会话
        for ($i = 0; $i < 5; $i++) {
            $sessionId = random_bytes(32);
            $session = new TLSSession(
                sessionId: $sessionId,
                masterSecret: random_bytes(48),
                cipherSuite: 'TLS_AES_128_GCM_SHA256',
                tlsVersion: 0x0303, // TLS 1.2
                timestamp: time()
            );
            
            $this->sessionIdManager->storeSession($session);
            
            // 验证会话存在
            $this->assertNotNull($this->sessionIdManager->getSession($sessionId));
        }
        
        // 清除所有会话
        $this->sessionIdManager->clearAllSessions();
        
        // 验证所有会话已被清除
        for ($i = 0; $i < 5; $i++) {
            $sessionId = random_bytes(32);
            $this->assertNull($this->sessionIdManager->getSession($sessionId));
        }
    }

    public function testSessionExpiration(): void
    {
        // 创建一个过期的会话（假设会话有效期为1小时，创建一个2小时前的会话）
        $sessionId = random_bytes(32);
        $session = new TLSSession(
            sessionId: $sessionId,
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time() - 7200 // 2小时前
        );

        // 存储会话
        $this->sessionIdManager->storeSession($session);
        
        // 验证过期会话不能被检索
        $this->assertNull($this->sessionIdManager->getSession($sessionId));
    }

    public function testAutoCleanupOfExpiredSessions(): void
    {
        // 创建一个未过期的会话
        $sessionId = random_bytes(32);
        $session = new TLSSession(
            sessionId: $sessionId,
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );
        
        // 存储会话
        $this->sessionIdManager->storeSession($session);
        
        // 创建一个过期的会话
        $expiredSessionId = random_bytes(32);
        $expiredSession = new TLSSession(
            sessionId: $expiredSessionId,
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time() - 7200 // 2小时前
        );
        
        // 存储过期会话
        $this->sessionIdManager->storeSession($expiredSession);
        
        // 验证未过期会话可以被检索
        $this->assertNotNull($this->sessionIdManager->getSession($sessionId));
        
        // 验证过期会话不能被检索
        $this->assertNull($this->sessionIdManager->getSession($expiredSessionId));
    }
} 
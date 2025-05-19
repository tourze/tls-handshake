<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Session\InMemorySessionManager;
use Tourze\TLSHandshake\Session\SessionInterface;

/**
 * 内存会话管理器测试
 */
class InMemorySessionManagerTest extends TestCase
{
    /**
     * 测试创建会话
     */
    public function testCreateSession(): void
    {
        $manager = new InMemorySessionManager();
        
        $cipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256
        $masterSecret = random_bytes(48);
        
        $session = $manager->createSession($cipherSuite, $masterSecret);
        
        // 验证会话基本属性
        $this->assertInstanceOf(SessionInterface::class, $session);
        $this->assertNotEmpty($session->getSessionId());
        $this->assertEquals($cipherSuite, $session->getCipherSuite());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
        $this->assertGreaterThanOrEqual(time() - 1, $session->getCreationTime());
        
        // 验证会话可以通过ID获取
        $retrievedSession = $manager->getSessionById($session->getSessionId());
        $this->assertNotNull($retrievedSession);
        $this->assertEquals($session->getSessionId(), $retrievedSession->getSessionId());
        $this->assertEquals($cipherSuite, $retrievedSession->getCipherSuite());
        $this->assertEquals($masterSecret, $retrievedSession->getMasterSecret());
    }
    
    /**
     * 测试存储会话
     */
    public function testStoreSession(): void
    {
        $manager = new InMemorySessionManager();
        
        // 创建一个会话
        $session1 = $manager->createSession(0x1301, random_bytes(48));
        $sessionId1 = $session1->getSessionId();
        
        // 修改会话并重新存储
        $session1->setCipherSuite(0x1302); // TLS_AES_256_GCM_SHA384
        $this->assertTrue($manager->storeSession($session1));
        
        // 验证修改后的会话
        $retrievedSession = $manager->getSessionById($sessionId1);
        $this->assertNotNull($retrievedSession);
        $this->assertEquals(0x1302, $retrievedSession->getCipherSuite());
    }
    
    /**
     * 测试删除会话
     */
    public function testRemoveSession(): void
    {
        $manager = new InMemorySessionManager();
        
        // 创建一个会话
        $session = $manager->createSession(0x1301, random_bytes(48));
        $sessionId = $session->getSessionId();
        
        // 验证会话存在
        $this->assertNotNull($manager->getSessionById($sessionId));
        
        // 删除会话
        $this->assertTrue($manager->removeSession($sessionId));
        
        // 验证会话已删除
        $this->assertNull($manager->getSessionById($sessionId));
        
        // 尝试删除不存在的会话
        $this->assertFalse($manager->removeSession('non_existent_id'));
    }
    
    /**
     * 测试清理过期会话
     */
    public function testCleanExpiredSessions(): void
    {
        $manager = new InMemorySessionManager();
        
        // 创建一个立即过期的会话（设置创建时间为过去）
        $session1 = $manager->createSession(0x1301, random_bytes(48));
        $session1->setLifetime(1); // 设置1秒有效期
        $session1->setCreationTime(time() - 10); // 设置为10秒前创建
        $manager->storeSession($session1);
        
        // 创建一个长期会话
        $session2 = $manager->createSession(0x1302, random_bytes(48));
        $session2->setLifetime(3600); // 设置1小时有效期
        $manager->storeSession($session2);
        
        // 验证第一个会话已过期
        $this->assertFalse($session1->isValid());
        
        // 验证第二个会话仍有效
        $this->assertTrue($session2->isValid());
        
        // 清理过期会话
        $cleanedCount = $manager->cleanExpiredSessions();
        
        // 验证清理了一个会话
        $this->assertEquals(1, $cleanedCount);
        
        // 验证过期会话已删除
        $this->assertNull($manager->getSessionById($session1->getSessionId()));
        
        // 验证有效会话仍存在
        $this->assertNotNull($manager->getSessionById($session2->getSessionId()));
    }
    
    /**
     * 测试获取未知会话
     */
    public function testGetUnknownSession(): void
    {
        $manager = new InMemorySessionManager();
        
        // 尝试获取不存在的会话
        $this->assertNull($manager->getSessionById('unknown_session_id'));
    }
} 
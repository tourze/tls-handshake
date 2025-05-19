<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Session\TLS13PSKSession;

/**
 * TLS 1.3 PSK会话测试
 */
class TLS13PSKSessionTest extends TestCase
{
    /**
     * 测试PSK会话基本功能
     */
    public function testBasicPSKSessionFunctionality(): void
    {
        $sessionId = bin2hex(random_bytes(16));
        $cipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256
        $masterSecret = random_bytes(48);
        $creationTime = time();
        $pskIdentity = bin2hex(random_bytes(16));
        $ticketAgeAdd = mt_rand(0, mt_getrandmax()) % (1 << 30);
        $ticketNonce = random_bytes(16);
        $resumptionMasterSecret = random_bytes(48);
        
        $session = new TLS13PSKSession(
            $sessionId,
            $cipherSuite,
            $masterSecret,
            $creationTime,
            $pskIdentity,
            $ticketAgeAdd,
            $ticketNonce,
            $resumptionMasterSecret
        );
        
        // 验证基本属性
        $this->assertEquals($sessionId, $session->getSessionId());
        $this->assertEquals('1301', $session->getCipherSuite());
        $this->assertEquals($masterSecret, $session->getMasterSecret());
        $this->assertEquals($creationTime, $session->getCreationTime());
        $this->assertEquals($pskIdentity, $session->getPskIdentity());
        $this->assertEquals($ticketAgeAdd, $session->getTicketAgeAdd());
        $this->assertEquals($ticketNonce, $session->getTicketNonce());
        $this->assertEquals($resumptionMasterSecret, $session->getResumptionMasterSecret());
        
        // 测试设置新值
        $newPskIdentity = bin2hex(random_bytes(16));
        $newTicketAgeAdd = mt_rand(0, mt_getrandmax()) % (1 << 30);
        $newTicketNonce = random_bytes(16);
        $newResumptionMasterSecret = random_bytes(48);
        
        $session->setPskIdentity($newPskIdentity)
            ->setTicketAgeAdd($newTicketAgeAdd)
            ->setTicketNonce($newTicketNonce)
            ->setResumptionMasterSecret($newResumptionMasterSecret);
        
        $this->assertEquals($newPskIdentity, $session->getPskIdentity());
        $this->assertEquals($newTicketAgeAdd, $session->getTicketAgeAdd());
        $this->assertEquals($newTicketNonce, $session->getTicketNonce());
        $this->assertEquals($newResumptionMasterSecret, $session->getResumptionMasterSecret());
    }
    
    /**
     * 测试早期数据支持
     */
    public function testEarlyDataSupport(): void
    {
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0x1301,
            random_bytes(48),
            time(),
            bin2hex(random_bytes(16)),
            mt_rand(0, mt_getrandmax()) % (1 << 30),
            random_bytes(16),
            random_bytes(48)
        );
        
        // 默认不允许早期数据
        $this->assertFalse($session->isEarlyDataAllowed());
        $this->assertEquals(0, $session->getMaxEarlyDataSize());
        
        // 启用早期数据
        $session->setEarlyDataAllowed(true);
        $this->assertTrue($session->isEarlyDataAllowed());
        
        // 设置早期数据大小
        $maxSize = 16384; // 16KB
        $session->setMaxEarlyDataSize($maxSize);
        $this->assertEquals($maxSize, $session->getMaxEarlyDataSize());
        $this->assertTrue($session->isEarlyDataAllowed()); // 设置大小大于0时自动启用
        
        // 设置大小为0应禁用早期数据
        $session->setMaxEarlyDataSize(0);
        $this->assertFalse($session->isEarlyDataAllowed());
        $this->assertEquals(0, $session->getMaxEarlyDataSize());
    }
    
    /**
     * 测试混淆票据年龄
     */
    public function testObfuscatedTicketAge(): void
    {
        $creationTime = time() - 1000; // 1000秒前
        $ticketAgeAdd = 123456789;
        
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0x1301,
            random_bytes(48),
            $creationTime,
            bin2hex(random_bytes(16)),
            $ticketAgeAdd,
            random_bytes(16),
            random_bytes(48)
        );
        
        // 当前时间
        $currentTime = time();
        
        // 计算期望的票据年龄（毫秒）
        $expectedTicketAge = ($currentTime - $creationTime) * 1000;
        
        // 计算期望的混淆票据年龄
        $expectedObfuscatedAge = ($expectedTicketAge + $ticketAgeAdd) % (1 << 32);
        
        // 验证混淆票据年龄
        $this->assertEquals($expectedObfuscatedAge, $session->getObfuscatedTicketAge($currentTime));
    }
    
    /**
     * 测试继承自TLSSession的功能
     */
    public function testParentSessionFunctionality(): void
    {
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            0x1301,
            random_bytes(48),
            time(),
            bin2hex(random_bytes(16)),
            mt_rand(0, mt_getrandmax()) % (1 << 30),
            random_bytes(16),
            random_bytes(48)
        );
        
        // 测试会话有效期（从父类继承）
        $this->assertEquals(3600, $session->getLifetime()); // 默认1小时
        $this->assertTrue($session->isValid());
        
        // 设置较短有效期
        $session->setLifetime(60); // 1分钟
        $this->assertEquals(60, $session->getLifetime());
        
        // 验证30秒后仍有效
        $this->assertTrue($session->isValid($session->getCreationTime() + 30));
        
        // 验证61秒后已过期
        $this->assertFalse($session->isValid($session->getCreationTime() + 61));
    }
} 
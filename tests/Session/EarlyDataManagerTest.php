<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Session\EarlyDataManager;
use Tourze\TLSHandshake\Session\TLS13PSKSession;

class EarlyDataManagerTest extends TestCase
{
    private EarlyDataManager $earlyDataManager;

    protected function setUp(): void
    {
        $this->earlyDataManager = new EarlyDataManager();
    }

    public function testCanStoreAndValidateEarlyData(): void
    {
        // 创建一个支持早期数据的PSK会话
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time(),
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );
        
        // 设置早期数据支持
        $session->setMaxEarlyDataSize(16384);

        // 存储早期数据
        $earlyData = random_bytes(1024); // 1KB的随机早期数据
        $earlyDataId = $this->earlyDataManager->storeEarlyData($session, $earlyData);
        
        // 验证早期数据ID不为空
        $this->assertNotEmpty($earlyDataId);
        
        // 验证早期数据可以被检索和验证
        $retrievedData = $this->earlyDataManager->getAndValidateEarlyData($session, $earlyDataId);
        
        $this->assertNotNull($retrievedData);
        $this->assertSame($earlyData, $retrievedData);
    }

    public function testRejectsEarlyDataExceedingMaxSize(): void
    {
        // 创建一个支持早期数据的PSK会话，最大早期数据大小为1KB
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time(),
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );
        
        // 设置早期数据支持
        $session->setMaxEarlyDataSize(1024); // 最大早期数据大小为1KB

        // 尝试存储超过最大大小的早期数据（2KB）
        $earlyData = random_bytes(2048);
        
        // 期望抛出异常
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Early data size exceeds maximum allowed size');
        
        $this->earlyDataManager->storeEarlyData($session, $earlyData);
    }

    public function testRejectsEarlyDataForExpiredSession(): void
    {
        // 创建一个过期的PSK会话
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time() - 7200, // 2小时前
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );
        
        // 设置早期数据支持
        $session->setMaxEarlyDataSize(16384);

        // 创建早期数据
        $earlyData = random_bytes(1024);
        
        // 存储早期数据（应该成功，因为我们还没有验证会话）
        $earlyDataId = $this->earlyDataManager->storeEarlyData($session, $earlyData);
        
        // 尝试验证早期数据（应该失败，因为会话已过期）
        $retrievedData = $this->earlyDataManager->getAndValidateEarlyData($session, $earlyDataId);
        
        $this->assertNull($retrievedData, '过期会话的早期数据不应该被验证');
    }

    public function testRejectsReplayedEarlyData(): void
    {
        // 创建一个支持早期数据的PSK会话
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time(),
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );
        
        // 设置早期数据支持
        $session->setMaxEarlyDataSize(16384);

        // 存储早期数据
        $earlyData = random_bytes(1024);
        $earlyDataId = $this->earlyDataManager->storeEarlyData($session, $earlyData);
        
        // 第一次验证早期数据（应该成功）
        $retrievedData = $this->earlyDataManager->getAndValidateEarlyData($session, $earlyDataId);
        $this->assertNotNull($retrievedData);
        
        // 第二次验证相同的早期数据（应该失败，防止重放攻击）
        $retrievedDataAgain = $this->earlyDataManager->getAndValidateEarlyData($session, $earlyDataId);
        $this->assertNull($retrievedDataAgain, '早期数据不应该被重复使用（防止重放攻击）');
    }

    public function testCanClearAllEarlyData(): void
    {
        // 创建一个支持早期数据的PSK会话
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 'TLS_AES_128_GCM_SHA256',
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time(),
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );
        
        // 设置早期数据支持
        $session->setMaxEarlyDataSize(16384);

        // 存储多条早期数据
        $earlyDataIds = [];
        for ($i = 0; $i < 5; $i++) {
            $earlyData = random_bytes(1024);
            $earlyDataIds[] = $this->earlyDataManager->storeEarlyData($session, $earlyData);
        }
        
        // 验证所有早期数据都存在
        foreach ($earlyDataIds as $earlyDataId) {
            $retrievedData = $this->earlyDataManager->getAndValidateEarlyData($session, $earlyDataId);
            $this->assertNotNull($retrievedData);
        }
        
        // 清除所有早期数据
        $this->earlyDataManager->clearAllEarlyData();
        
        // 验证所有早期数据都已被清除
        foreach ($earlyDataIds as $earlyDataId) {
            $retrievedData = $this->earlyDataManager->getAndValidateEarlyData($session, $earlyDataId);
            $this->assertNull($retrievedData, '早期数据应该已被清除');
        }
    }
} 
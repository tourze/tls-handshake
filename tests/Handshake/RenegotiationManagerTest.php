<?php

namespace Tourze\TLSHandshake\Tests\Handshake;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Extension\RenegotiationInfoExtension;
use Tourze\TLSHandshake\Handshake\RenegotiationManager;
use Tourze\TLSHandshake\Protocol\TLSVersion;

/**
 * 重协商管理器测试类
 */
class RenegotiationManagerTest extends TestCase
{
    /**
     * 测试创建重协商管理器
     */
    public function testCreateRenegotiationManager(): void
    {
        $manager = new RenegotiationManager();
        $this->assertFalse($manager->isRenegotiating());
        $this->assertFalse($manager->isSecureRenegotiation());
    }
    
    /**
     * 测试设置安全重协商
     */
    public function testSetSecureRenegotiation(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);
        $this->assertTrue($manager->isSecureRenegotiation());
        
        $manager->setSecureRenegotiation(false);
        $this->assertFalse($manager->isSecureRenegotiation());
    }
    
    /**
     * 测试开始重协商
     */
    public function testStartRenegotiation(): void
    {
        $manager = new RenegotiationManager();
        $this->assertFalse($manager->isRenegotiating());
        
        $manager->startRenegotiation();
        $this->assertTrue($manager->isRenegotiating());
    }
    
    /**
     * 测试结束重协商
     */
    public function testEndRenegotiation(): void
    {
        $manager = new RenegotiationManager();
        $manager->startRenegotiation();
        $this->assertTrue($manager->isRenegotiating());
        
        $manager->endRenegotiation();
        $this->assertFalse($manager->isRenegotiating());
    }
    
    /**
     * 测试生成初始安全重协商扩展
     */
    public function testCreateInitialRenegotiationInfoExtension(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);
        
        $extension = $manager->createRenegotiationInfoExtension();
        $this->assertInstanceOf(RenegotiationInfoExtension::class, $extension);
        $this->assertEmpty($extension->getRenegotiatedConnection());
    }
    
    /**
     * 测试处理客户端重协商扩展
     */
    public function testProcessClientRenegotiationExtension(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);
        
        // 第一次握手，客户端的扩展应该为空
        $clientExtension = new RenegotiationInfoExtension();
        $result = $manager->processClientRenegotiationExtension($clientExtension);
        $this->assertTrue($result);
        
        // 模拟重协商
        $manager->storeClientVerifyData('client_verify_data');
        $manager->storeServerVerifyData('server_verify_data');
        $manager->startRenegotiation();
        
        // 客户端应该提供正确的验证数据
        $correctData = 'client_verify_data';
        $clientExtension = new RenegotiationInfoExtension();
        $clientExtension->setRenegotiatedConnection($correctData);
        $result = $manager->processClientRenegotiationExtension($clientExtension);
        $this->assertTrue($result);
        
        // 错误的验证数据应该被拒绝
        $incorrectData = 'wrong_verify_data';
        $clientExtension = new RenegotiationInfoExtension();
        $clientExtension->setRenegotiatedConnection($incorrectData);
        $result = $manager->processClientRenegotiationExtension($clientExtension);
        $this->assertFalse($result);
    }
    
    /**
     * 测试生成服务器重协商扩展
     */
    public function testCreateServerRenegotiationExtension(): void
    {
        $manager = new RenegotiationManager();
        $manager->setSecureRenegotiation(true);
        
        // 初始握手
        $extension = $manager->createServerRenegotiationInfoExtension();
        $this->assertInstanceOf(RenegotiationInfoExtension::class, $extension);
        $this->assertEmpty($extension->getRenegotiatedConnection());
        
        // 模拟重协商
        $manager->storeClientVerifyData('client_verify_data');
        $manager->storeServerVerifyData('server_verify_data');
        $manager->startRenegotiation();
        
        // 重协商时，服务器应提供客户端和服务器的验证数据
        $extension = $manager->createServerRenegotiationInfoExtension();
        $this->assertInstanceOf(RenegotiationInfoExtension::class, $extension);
        $this->assertEquals('client_verify_dataserver_verify_data', $extension->getRenegotiatedConnection());
    }
    
    /**
     * 测试重协商次数限制
     */
    public function testRenegotiationLimits(): void
    {
        $manager = new RenegotiationManager();
        $manager->setRenegotiationLimit(2);
        
        // 第一次重协商
        $this->assertTrue($manager->canRenegotiate());
        $manager->incrementRenegotiationCount();
        
        // 第二次重协商
        $this->assertTrue($manager->canRenegotiate());
        $manager->incrementRenegotiationCount();
        
        // 第三次重协商应该被拒绝
        $this->assertFalse($manager->canRenegotiate());
    }
    
    /**
     * 测试TLS 1.3不支持重协商
     */
    public function testTLS13NoRenegotiation(): void
    {
        $manager = new RenegotiationManager();
        $this->assertFalse($manager->isSupportedForVersion(TLSVersion::TLS_1_3));
        $this->assertTrue($manager->isSupportedForVersion(TLSVersion::TLS_1_2));
    }
} 
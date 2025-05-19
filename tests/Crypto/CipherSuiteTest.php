<?php

namespace Tourze\TLSHandshake\Tests\Crypto;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\CipherSuite;

/**
 * CipherSuite类测试
 */
class CipherSuiteTest extends TestCase
{
    /**
     * 测试获取加密套件值
     */
    public function testGetValue(): void
    {
        $cipherSuite = new CipherSuite(CipherSuite::TLS_AES_128_GCM_SHA256);
        $this->assertEquals(CipherSuite::TLS_AES_128_GCM_SHA256, $cipherSuite->getValue());
    }
    
    /**
     * 测试获取加密套件名称
     */
    public function testGetName(): void
    {
        $cipherSuite = new CipherSuite(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        $this->assertEquals('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', $cipherSuite->getName());
        
        // 测试未知加密套件
        $unknownCipherSuite = new CipherSuite(0x9999);
        $this->assertEquals('Unknown CipherSuite (0x9999)', $unknownCipherSuite->getName());
    }
    
    /**
     * 测试判断是否为TLS 1.3加密套件
     */
    public function testIsTLS13(): void
    {
        // TLS 1.3加密套件
        $tls13CipherSuite = new CipherSuite(CipherSuite::TLS_AES_128_GCM_SHA256);
        $this->assertTrue($tls13CipherSuite->isTLS13());
        
        // TLS 1.2加密套件
        $tls12CipherSuite = new CipherSuite(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        $this->assertFalse($tls12CipherSuite->isTLS13());
    }
    
    /**
     * 测试获取加密套件名称（静态方法）
     */
    public function testGetCipherSuiteName(): void
    {
        $this->assertEquals('TLS_RSA_WITH_AES_128_CBC_SHA', CipherSuite::getCipherSuiteName(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA));
        $this->assertEquals('TLS_AES_256_GCM_SHA384', CipherSuite::getCipherSuiteName(CipherSuite::TLS_AES_256_GCM_SHA384));
    }
    
    /**
     * 测试获取推荐的TLS 1.2加密套件列表
     */
    public function testGetRecommendedTLS12CipherSuites(): void
    {
        $suites = CipherSuite::getRecommendedTLS12CipherSuites();
        
        // 检查返回的是否为数组
        $this->assertIsArray($suites);
        
        // 检查是否包含预期的加密套件
        $this->assertContains(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, $suites);
        $this->assertContains(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA, $suites);
        
        // 检查第一个是否为最高优先级的套件
        $this->assertEquals(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, $suites[0]);
    }
    
    /**
     * 测试获取推荐的TLS 1.3加密套件列表
     */
    public function testGetRecommendedTLS13CipherSuites(): void
    {
        $suites = CipherSuite::getRecommendedTLS13CipherSuites();
        
        // 检查返回的是否为数组
        $this->assertIsArray($suites);
        
        // 检查是否包含预期的加密套件
        $this->assertContains(CipherSuite::TLS_AES_256_GCM_SHA384, $suites);
        $this->assertContains(CipherSuite::TLS_AES_128_GCM_SHA256, $suites);
        
        // 检查第一个是否为最高优先级的套件
        $this->assertEquals(CipherSuite::TLS_AES_256_GCM_SHA384, $suites[0]);
    }
} 
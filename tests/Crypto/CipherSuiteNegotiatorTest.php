<?php

namespace Tourze\TLSHandshake\Tests\Crypto;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\CipherSuite;
use Tourze\TLSHandshake\Crypto\CipherSuiteNegotiator;
use Tourze\TLSHandshake\Protocol\TLSVersion;

/**
 * CipherSuiteNegotiator类测试
 */
class CipherSuiteNegotiatorTest extends TestCase
{
    /**
     * 测试构造函数和基本属性
     */
    public function testConstructor(): void
    {
        // 使用默认推荐加密套件
        $negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_2);
        $this->assertEquals(TLSVersion::TLS_1_2, $negotiator->getVersion());
        $this->assertEquals(CipherSuite::getRecommendedTLS12CipherSuites(), $negotiator->getServerCipherSuites());
        
        // 使用自定义加密套件
        $customCipherSuites = [
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA
        ];
        $negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_2, $customCipherSuites);
        $this->assertEquals($customCipherSuites, $negotiator->getServerCipherSuites());
        
        // TLS 1.3版本
        $negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_3);
        $this->assertEquals(CipherSuite::getRecommendedTLS13CipherSuites(), $negotiator->getServerCipherSuites());
    }
    
    /**
     * 测试版本设置和获取
     */
    public function testVersionSetterGetter(): void
    {
        $negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_2);
        $this->assertEquals(TLSVersion::TLS_1_2, $negotiator->getVersion());
        
        $negotiator->setVersion(TLSVersion::TLS_1_3);
        $this->assertEquals(TLSVersion::TLS_1_3, $negotiator->getVersion());
    }
    
    /**
     * 测试加密套件列表设置和获取
     */
    public function testCipherSuitesSetterGetter(): void
    {
        $negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_2);
        
        $customCipherSuites = [
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA
        ];
        $negotiator->setServerCipherSuites($customCipherSuites);
        $this->assertEquals($customCipherSuites, $negotiator->getServerCipherSuites());
        
        // 测试添加加密套件
        $negotiator->addServerCipherSuite(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA);
        $expected = [
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA
        ];
        $this->assertEquals($expected, $negotiator->getServerCipherSuites());
        
        // 测试添加已存在的加密套件不会重复添加
        $negotiator->addServerCipherSuite(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA);
        $this->assertEquals($expected, $negotiator->getServerCipherSuites());
    }
    
    /**
     * 测试TLS 1.2加密套件协商
     */
    public function testNegotiateTLS12(): void
    {
        $serverCipherSuites = [
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA
        ];
        
        $negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_2, $serverCipherSuites);
        
        // 客户端支持所有服务器支持的加密套件
        $clientCipherSuites = [
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ];
        
        // 应该选择服务器最高优先级的套件
        $selected = $negotiator->negotiate($clientCipherSuites);
        $this->assertEquals(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, $selected);
        
        // 客户端只支持服务器较低优先级的套件
        $clientCipherSuites = [
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA
        ];
        
        // 应该选择服务器支持的客户端最高优先级的套件
        $selected = $negotiator->negotiate($clientCipherSuites);
        $this->assertEquals(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA, $selected);
        
        // 客户端不支持服务器的任何套件
        $clientCipherSuites = [
            CipherSuite::TLS_RSA_WITH_NULL_MD5,
            CipherSuite::TLS_RSA_WITH_NULL_SHA
        ];
        
        // 应该返回null
        $selected = $negotiator->negotiate($clientCipherSuites);
        $this->assertNull($selected);
        
        // 客户端包含TLS 1.3套件，但协商是TLS 1.2
        $clientCipherSuites = [
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA
        ];
        
        // 应该过滤掉TLS 1.3套件，选择TLS 1.2套件
        $selected = $negotiator->negotiate($clientCipherSuites);
        $this->assertEquals(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA, $selected);
    }
    
    /**
     * 测试TLS 1.3加密套件协商
     */
    public function testNegotiateTLS13(): void
    {
        $serverCipherSuites = [
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_AES_128_GCM_SHA256
        ];
        
        $negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_3, $serverCipherSuites);
        
        // 客户端支持所有服务器支持的加密套件
        $clientCipherSuites = [
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        ];
        
        // 应该选择服务器最高优先级的套件
        $selected = $negotiator->negotiate($clientCipherSuites);
        $this->assertEquals(CipherSuite::TLS_AES_256_GCM_SHA384, $selected);
        
        // 客户端只支持服务器较低优先级的套件
        $clientCipherSuites = [
            CipherSuite::TLS_AES_128_GCM_SHA256
        ];
        
        // 应该选择服务器支持的客户端套件
        $selected = $negotiator->negotiate($clientCipherSuites);
        $this->assertEquals(CipherSuite::TLS_AES_128_GCM_SHA256, $selected);
        
        // 客户端不支持服务器的任何TLS 1.3套件
        $clientCipherSuites = [
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA
        ];
        
        // 应该返回null
        $selected = $negotiator->negotiate($clientCipherSuites);
        $this->assertNull($selected);
    }
    
    /**
     * 测试加密套件安全性检查
     */
    public function testCipherSuiteSecurity(): void
    {
        // 安全的加密套件
        $this->assertTrue(CipherSuiteNegotiator::isCipherSuiteSecure(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384));
        $this->assertTrue(CipherSuiteNegotiator::isCipherSuiteSecure(CipherSuite::TLS_AES_256_GCM_SHA384));
        
        // 不安全的加密套件
        $this->assertFalse(CipherSuiteNegotiator::isCipherSuiteSecure(CipherSuite::TLS_RSA_WITH_NULL_MD5));
        $this->assertFalse(CipherSuiteNegotiator::isCipherSuiteSecure(CipherSuite::TLS_RSA_WITH_NULL_SHA));
    }
} 
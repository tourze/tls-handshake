<?php

namespace Tourze\TLSHandshake\Tests\Config;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Config\HandshakeConfig;

class HandshakeConfigTest extends TestCase
{
    /**
     * 测试握手配置的基本功能
     */
    public function testBasicConfiguration()
    {
        $config = new HandshakeConfig();
        
        // 测试默认值
        $this->assertFalse($config->isServerMode());
        $this->assertEquals(['TLS 1.2', 'TLS 1.3'], $config->getSupportedVersions());
        
        // 测试设置和获取服务器模式
        $config->setServerMode(true);
        $this->assertTrue($config->isServerMode());
        
        // 测试设置和获取支持的版本
        $config->setSupportedVersions(['TLS 1.2']);
        $this->assertEquals(['TLS 1.2'], $config->getSupportedVersions());
    }
    
    /**
     * 测试加密套件配置
     */
    public function testCipherSuiteConfiguration()
    {
        $config = new HandshakeConfig();
        
        // 默认应该有一些加密套件
        $this->assertNotEmpty($config->getSupportedCipherSuites());
        
        // 测试设置和获取支持的加密套件
        $suites = ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'];
        $config->setSupportedCipherSuites($suites);
        $this->assertEquals($suites, $config->getSupportedCipherSuites());
    }
    
    /**
     * 测试证书配置
     */
    public function testCertificateConfiguration()
    {
        $config = new HandshakeConfig();
        
        // 默认没有证书路径
        $this->assertNull($config->getCertificatePath());
        
        // 测试设置和获取证书路径
        $config->setCertificatePath('/path/to/cert.pem');
        $this->assertEquals('/path/to/cert.pem', $config->getCertificatePath());
        
        // 测试设置和获取私钥路径
        $config->setPrivateKeyPath('/path/to/key.pem');
        $this->assertEquals('/path/to/key.pem', $config->getPrivateKeyPath());
    }
    
    /**
     * 测试扩展配置
     */
    public function testExtensionConfiguration()
    {
        $config = new HandshakeConfig();
        
        // 测试启用的扩展
        $config->enableExtension('signature_algorithms');
        $this->assertTrue($config->isExtensionEnabled('signature_algorithms'));
        
        // 测试禁用的扩展
        $config->disableExtension('signature_algorithms');
        $this->assertFalse($config->isExtensionEnabled('signature_algorithms'));
    }
}

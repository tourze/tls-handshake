<?php

namespace Tourze\TLSHandshake\Tests\Crypto\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\KeyExchange\DHEKeyExchange;
use Tourze\TLSHandshake\Crypto\KeyExchange\ECDHEKeyExchange;
use Tourze\TLSHandshake\Crypto\KeyExchange\KeyExchangeFactory;
use Tourze\TLSHandshake\Crypto\KeyExchange\PSKKeyExchange;
use Tourze\TLSHandshake\Crypto\KeyExchange\RSAKeyExchange;
use Tourze\TLSHandshake\Crypto\KeyExchange\TLS13KeyExchange;

/**
 * 密钥交换工厂测试
 */
class KeyExchangeFactoryTest extends TestCase
{
    /**
     * 测试创建RSA密钥交换实例
     */
    public function testCreateRSAKeyExchange(): void
    {
        $keyExchange = KeyExchangeFactory::create('RSA');
        $this->assertInstanceOf(RSAKeyExchange::class, $keyExchange);
    }
    
    /**
     * 测试创建DHE密钥交换实例
     */
    public function testCreateDHEKeyExchange(): void
    {
        $keyExchange = KeyExchangeFactory::create('DHE');
        $this->assertInstanceOf(DHEKeyExchange::class, $keyExchange);
    }
    
    /**
     * 测试创建ECDHE密钥交换实例
     */
    public function testCreateECDHEKeyExchange(): void
    {
        $keyExchange = KeyExchangeFactory::create('ECDHE');
        $this->assertInstanceOf(ECDHEKeyExchange::class, $keyExchange);
    }
    
    /**
     * 测试创建PSK密钥交换实例
     */
    public function testCreatePSKKeyExchange(): void
    {
        $keyExchange = KeyExchangeFactory::create('PSK');
        $this->assertInstanceOf(PSKKeyExchange::class, $keyExchange);
    }
    
    /**
     * 测试创建TLS 1.3密钥交换实例
     */
    public function testCreateTLS13KeyExchange(): void
    {
        $keyExchange = KeyExchangeFactory::create('TLS13');
        $this->assertInstanceOf(TLS13KeyExchange::class, $keyExchange);
    }
    
    /**
     * 测试创建不支持的密钥交换类型抛出异常
     */
    public function testCreateUnsupportedTypeThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported key exchange type: INVALID');
        
        KeyExchangeFactory::create('INVALID');
    }
    
    /**
     * 测试根据TLS 1.2加密套件创建密钥交换实例
     */
    public function testCreateFromCipherSuiteTLS12(): void
    {
        // TLS 1.2版本
        $tlsVersion = 0x0303;
        
        // 测试RSA加密套件
        $keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_RSA_WITH_AES_128_GCM_SHA256', $tlsVersion);
        $this->assertInstanceOf(RSAKeyExchange::class, $keyExchange);
        
        // 测试DHE_RSA加密套件
        $keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', $tlsVersion);
        $this->assertInstanceOf(DHEKeyExchange::class, $keyExchange);
        
        // 测试ECDHE_RSA加密套件
        $keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', $tlsVersion);
        $this->assertInstanceOf(ECDHEKeyExchange::class, $keyExchange);
        
        // 测试PSK加密套件
        $keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_PSK_WITH_AES_128_GCM_SHA256', $tlsVersion);
        $this->assertInstanceOf(PSKKeyExchange::class, $keyExchange);
    }
    
    /**
     * 测试根据TLS 1.3加密套件创建密钥交换实例
     */
    public function testCreateFromCipherSuiteTLS13(): void
    {
        // TLS 1.3版本
        $tlsVersion = 0x0304;
        
        // TLS 1.3中，任何加密套件都使用TLS13KeyExchange
        $keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_AES_128_GCM_SHA256', $tlsVersion);
        $this->assertInstanceOf(TLS13KeyExchange::class, $keyExchange);
        
        $keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_AES_256_GCM_SHA384', $tlsVersion);
        $this->assertInstanceOf(TLS13KeyExchange::class, $keyExchange);
        
        $keyExchange = KeyExchangeFactory::createFromCipherSuite('TLS_CHACHA20_POLY1305_SHA256', $tlsVersion);
        $this->assertInstanceOf(TLS13KeyExchange::class, $keyExchange);
    }
} 
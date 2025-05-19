<?php

declare(strict_types=1);

namespace Tourze\TLSHandshake\Tests\Crypto\KeyDerivation;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\KeyDerivation\VerifyDataGenerator;

/**
 * 验证数据生成测试
 */
class VerifyDataGeneratorTest extends TestCase
{
    /**
     * 测试TLS 1.2客户端验证数据生成
     */
    public function testTLS12ClientVerifyData(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec';
        
        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);
        
        $this->assertNotEmpty($verifyData);
        $this->assertSame(12, strlen($verifyData)); // TLS 1.2验证数据为12字节
    }
    
    /**
     * 测试TLS 1.2服务器验证数据生成
     */
    public function testTLS12ServerVerifyData(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec + Finished';
        
        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS12ServerVerifyData($masterSecret, $handshakeMessages);
        
        $this->assertNotEmpty($verifyData);
        $this->assertSame(12, strlen($verifyData)); // TLS 1.2验证数据为12字节
    }
    
    /**
     * 测试TLS 1.3客户端验证数据生成
     */
    public function testTLS13ClientVerifyData(): void
    {
        $baseKey = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate + CertificateVerify';
        
        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS13ClientVerifyData($baseKey, $handshakeContext);
        
        $this->assertNotEmpty($verifyData);
    }
    
    /**
     * 测试TLS 1.3服务器验证数据生成
     */
    public function testTLS13ServerVerifyData(): void
    {
        $baseKey = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished';
        
        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS13ServerVerifyData($baseKey, $handshakeContext);
        
        $this->assertNotEmpty($verifyData);
    }
    
    /**
     * 测试相同输入产生相同验证数据
     */
    public function testConsistency(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec';
        
        $generator = new VerifyDataGenerator();
        $verify1 = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);
        $verify2 = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);
        
        $this->assertSame($verify1, $verify2);
    }
    
    /**
     * 测试不同消息产生不同验证数据
     */
    public function testDifferentMessages(): void
    {
        $masterSecret = random_bytes(48);
        $messages1 = 'ClientHello + ServerHello';
        $messages2 = 'ClientHello + ServerHello + Certificate';
        
        $generator = new VerifyDataGenerator();
        $verify1 = $generator->generateTLS12ClientVerifyData($masterSecret, $messages1);
        $verify2 = $generator->generateTLS12ClientVerifyData($masterSecret, $messages2);
        
        $this->assertNotSame($verify1, $verify2);
    }
}

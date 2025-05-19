<?php

declare(strict_types=1);

namespace Tourze\TLSHandshake\Tests\Crypto\KeyDerivation;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\KeyDerivation\SessionKeysDeriver;

/**
 * 会话密钥派生测试
 */
class SessionKeysDeriverTest extends TestCase
{
    /**
     * 测试TLS 1.2会话密钥派生
     */
    public function testTLS12SessionKeysDerivation(): void
    {
        $masterSecret = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);
        $cipherSuite = 0xC02F; // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        
        $deriver = new SessionKeysDeriver();
        $keys = $deriver->deriveTLS12Keys($masterSecret, $clientRandom, $serverRandom, $cipherSuite);
        
        $this->assertNotEmpty($keys->clientWriteKey);
        $this->assertNotEmpty($keys->serverWriteKey);
        $this->assertNotEmpty($keys->clientWriteIV);
        $this->assertNotEmpty($keys->serverWriteIV);
    }
    
    /**
     * 测试TLS 1.3会话密钥派生
     */
    public function testTLS13SessionKeysDerivation(): void
    {
        $handshakeTraffic = random_bytes(32);
        $cipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256
        
        $deriver = new SessionKeysDeriver();
        $handshakeKeys = $deriver->deriveTLS13HandshakeKeys($handshakeTraffic, $cipherSuite);
        
        $this->assertNotEmpty($handshakeKeys->clientWriteKey);
        $this->assertNotEmpty($handshakeKeys->serverWriteKey);
        $this->assertNotEmpty($handshakeKeys->clientWriteIV);
        $this->assertNotEmpty($handshakeKeys->serverWriteIV);
        
        // 测试应用数据密钥
        $applicationTraffic = random_bytes(32);
        $applicationKeys = $deriver->deriveTLS13ApplicationKeys($applicationTraffic, $cipherSuite);
        
        $this->assertNotEmpty($applicationKeys->clientWriteKey);
        $this->assertNotEmpty($applicationKeys->serverWriteKey);
        $this->assertNotEmpty($applicationKeys->clientWriteIV);
        $this->assertNotEmpty($applicationKeys->serverWriteIV);
    }
    
    /**
     * 测试相同输入产生相同密钥
     */
    public function testConsistency(): void
    {
        $masterSecret = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);
        $cipherSuite = 0xC02F; // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        
        $deriver = new SessionKeysDeriver();
        $keys1 = $deriver->deriveTLS12Keys($masterSecret, $clientRandom, $serverRandom, $cipherSuite);
        $keys2 = $deriver->deriveTLS12Keys($masterSecret, $clientRandom, $serverRandom, $cipherSuite);
        
        $this->assertSame($keys1->clientWriteKey, $keys2->clientWriteKey);
        $this->assertSame($keys1->serverWriteKey, $keys2->serverWriteKey);
        $this->assertSame($keys1->clientWriteIV, $keys2->clientWriteIV);
        $this->assertSame($keys1->serverWriteIV, $keys2->serverWriteIV);
    }
    
    /**
     * 测试不同密码套件产生不同长度的密钥
     */
    public function testDifferentCipherSuites(): void
    {
        $masterSecret = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);
        
        $deriver = new SessionKeysDeriver();
        
        $keys128 = $deriver->deriveTLS12Keys(
            $masterSecret, 
            $clientRandom, 
            $serverRandom, 
            0xC02F // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        );
        
        $keys256 = $deriver->deriveTLS12Keys(
            $masterSecret, 
            $clientRandom, 
            $serverRandom, 
            0xC030 // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        );
        
        $this->assertSame(16, strlen($keys128->clientWriteKey)); // AES-128用16字节密钥
        $this->assertSame(32, strlen($keys256->clientWriteKey)); // AES-256用32字节密钥
    }
}

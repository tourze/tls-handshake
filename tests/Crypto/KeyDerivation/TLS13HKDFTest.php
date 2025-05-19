<?php

declare(strict_types=1);

namespace Tourze\TLSHandshake\Tests\Crypto\KeyDerivation;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\KeyDerivation\TLS13HKDF;

/**
 * TLS 1.3 HKDF测试
 */
class TLS13HKDFTest extends TestCase
{
    /**
     * 测试HKDF-Extract函数
     */
    public function testExtract(): void
    {
        $hkdf = new TLS13HKDF();
        $salt = random_bytes(32);
        $ikm = random_bytes(32);
        
        $result = $hkdf->extract($salt, $ikm);
        
        $this->assertNotEmpty($result);
        $this->assertSame(32, strlen($result)); // SHA-256输出长度为32字节
    }
    
    /**
     * 测试HKDF-Expand-Label函数
     */
    public function testExpandLabel(): void
    {
        $hkdf = new TLS13HKDF();
        $secret = random_bytes(32);
        $label = 'derived';
        $context = '';
        
        $result1 = $hkdf->expandLabel($secret, $label, $context, 16);
        $result2 = $hkdf->expandLabel($secret, $label, $context, 32);
        
        $this->assertSame(16, strlen($result1));
        $this->assertSame(32, strlen($result2));
        
        // 测试相同输入产生相同输出
        $result3 = $hkdf->expandLabel($secret, $label, $context, 32);
        $this->assertSame($result2, $result3);
    }
    
    /**
     * 测试Derive-Secret函数
     */
    public function testDeriveSecret(): void
    {
        $hkdf = new TLS13HKDF();
        $secret = random_bytes(32);
        $label = 'c hs traffic';
        $messages = 'ClientHello + ServerHello';
        
        $result = $hkdf->deriveSecret($secret, $label, $messages);
        
        $this->assertNotEmpty($result);
        $this->assertSame(32, strlen($result)); // SHA-256输出长度为32字节
        
        // 测试不同消息产生不同输出
        $result2 = $hkdf->deriveSecret($secret, $label, 'Different messages');
        $this->assertNotSame($result, $result2);
    }
    
    /**
     * 测试RFC 8446中的HKDF测试向量
     * 注意：这是一个假设的测试向量，实际实现中应替换为规范中的真实测试向量
     */
    public function testHKDFVectors(): void
    {
        $hkdf = new TLS13HKDF();
        
        // 测试向量（在实际实现中替换为真实测试数据）
        $ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $salt = hex2bin('000102030405060708090a0b0c');
        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
        $length = 42;
        
        $prk = $hkdf->extract($salt, $ikm);
        $result = $hkdf->expand($prk, $info, $length);
        
        $this->assertSame($length, strlen($result));
        $this->assertNotEmpty($result);
    }
}

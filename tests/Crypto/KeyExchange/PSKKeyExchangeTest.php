<?php

namespace Tourze\TLSHandshake\Tests\Crypto\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\KeyExchange\PSKKeyExchange;

/**
 * PSK密钥交换测试
 */
class PSKKeyExchangeTest extends TestCase
{
    /**
     * 测试设置和获取PSK身份
     */
    public function testSetAndGetIdentity(): void
    {
        $exchange = new PSKKeyExchange();
        $identity = 'client1';
        $psk = hex2bin('0123456789abcdef0123456789abcdef');
        
        $exchange->setPSK($identity, $psk);
        $this->assertEquals($identity, $exchange->getIdentity());
    }
    
    /**
     * 测试生成预主密钥
     */
    public function testGeneratePreMasterSecret(): void
    {
        $exchange = new PSKKeyExchange();
        $identity = 'client1';
        $psk = hex2bin('0123456789abcdef0123456789abcdef');
        
        $exchange->setPSK($identity, $psk);
        $preMasterSecret = $exchange->generatePreMasterSecret();
        
        // 验证预主密钥不为空
        $this->assertNotEmpty($preMasterSecret);
        
        // 验证预主密钥格式正确
        // 前两个字节应该是其他密钥长度（0）
        $this->assertEquals(0, unpack('n', substr($preMasterSecret, 0, 2))[1]);
        
        // 接下来的两个字节应该是PSK长度
        $pskLength = unpack('n', substr($preMasterSecret, 2 + 0, 2))[1];
        $this->assertEquals(strlen($psk), $pskLength);
        
        // 接下来的字节应该是PSK
        $extractedPsk = substr($preMasterSecret, 2 + 0 + 2);
        $this->assertEquals($psk, $extractedPsk);
    }
    
    /**
     * 测试格式化PSK身份
     */
    public function testFormatIdentity(): void
    {
        $exchange = new PSKKeyExchange();
        $identity = 'client1';
        $psk = hex2bin('0123456789abcdef0123456789abcdef');
        
        $exchange->setPSK($identity, $psk);
        $formattedIdentity = $exchange->formatIdentity();
        
        // 验证格式化身份结构：身份长度(2字节) + 身份
        $expectedLength = strlen($identity);
        $this->assertEquals($expectedLength, unpack('n', substr($formattedIdentity, 0, 2))[1]);
        $this->assertEquals($identity, substr($formattedIdentity, 2));
    }
    
    /**
     * 测试未设置PSK时生成预主密钥抛出异常
     */
    public function testGeneratePreMasterSecretWithoutPSKThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('PSK not set');
        
        $exchange = new PSKKeyExchange();
        $exchange->generatePreMasterSecret();
    }
    
    /**
     * 测试未设置身份时格式化身份抛出异常
     */
    public function testFormatIdentityWithoutIdentityThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('PSK identity not set');
        
        $exchange = new PSKKeyExchange();
        $exchange->formatIdentity();
    }
    
    /**
     * 测试获取预主密钥
     */
    public function testGetPreMasterSecret(): void
    {
        $exchange = new PSKKeyExchange();
        $identity = 'client1';
        $psk = hex2bin('0123456789abcdef0123456789abcdef');
        
        $exchange->setPSK($identity, $psk);
        $originalPreMasterSecret = $exchange->generatePreMasterSecret();
        
        // 验证getPreMasterSecret返回正确的预主密钥
        $this->assertEquals($originalPreMasterSecret, $exchange->getPreMasterSecret());
    }
} 
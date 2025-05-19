<?php

declare(strict_types=1);

namespace Tourze\TLSHandshake\Tests\Crypto\KeyDerivation;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\KeyDerivation\MasterSecretDeriver;

/**
 * 主密钥派生测试
 */
class MasterSecretDeriverTest extends TestCase
{
    /**
     * 测试TLS 1.2主密钥派生
     */
    public function testTLS12MasterSecretDerivation(): void
    {
        $premaster = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);
        
        $deriver = new MasterSecretDeriver();
        $master = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);
        
        $this->assertNotEmpty($master);
        $this->assertSame(48, strlen($master));
    }
    
    /**
     * 测试TLS 1.3主密钥派生
     */
    public function testTLS13MasterSecretDerivation(): void
    {
        $handshakeSecret = random_bytes(32);
        
        $deriver = new MasterSecretDeriver();
        $master = $deriver->deriveTLS13($handshakeSecret);
        
        $this->assertNotEmpty($master);
        $this->assertSame(32, strlen($master)); // SHA-256哈希输出长度
    }
    
    /**
     * 测试TLS 1.2相同输入产生相同密钥
     */
    public function testTLS12Consistency(): void
    {
        $premaster = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);
        
        $deriver = new MasterSecretDeriver();
        $master1 = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);
        $master2 = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);
        
        $this->assertSame($master1, $master2);
    }
    
    /**
     * 测试TLS 1.3相同输入产生相同密钥
     */
    public function testTLS13Consistency(): void
    {
        $handshakeSecret = random_bytes(32);
        
        $deriver = new MasterSecretDeriver();
        $master1 = $deriver->deriveTLS13($handshakeSecret);
        $master2 = $deriver->deriveTLS13($handshakeSecret);
        
        $this->assertSame($master1, $master2);
    }
    
    /**
     * 测试TLS 1.2密钥导出向量
     * 注意：这是一个假设的测试向量，实际实现中应替换为真实测试数据
     */
    public function testTLS12Vectors(): void
    {
        $premaster = hex2bin('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');
        $clientRandom = hex2bin('4041424344454647484a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f');
        $serverRandom = hex2bin('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
        
        $deriver = new MasterSecretDeriver();
        $master = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);
        
        $this->assertSame(48, strlen($master));
        $this->assertNotEmpty($master);
    }
}

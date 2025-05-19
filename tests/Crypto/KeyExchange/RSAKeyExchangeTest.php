<?php

namespace Tourze\TLSHandshake\Tests\Crypto\KeyExchange;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\KeyExchange\RSAKeyExchange;

/**
 * RSA密钥交换测试
 */
class RSAKeyExchangeTest extends TestCase
{
    /**
     * 测试公钥设置和获取
     */
    public function testSetAndGetServerPublicKey(): void
    {
        $exchange = new RSAKeyExchange();
        $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqUm\ntYTNPYQGQykP0GCc\n1SecN4PXgbgokH+NE5oK3M/hCYV2FfvtgcuaKrWrLzN3IFS\nFKWXm6UZ5AhvBnQQP\nxLKHx3Pu4Q==\n-----END PUBLIC KEY-----";
        
        $exchange->setServerPublicKey($publicKey);
        $this->assertEquals($publicKey, $exchange->getServerPublicKey());
    }
    
    /**
     * 测试生成预主密钥
     */
    public function testGeneratePreMasterSecret(): void
    {
        $exchange = new RSAKeyExchange();
        $version = 0x0303; // TLS 1.2
        
        $preMasterSecret = $exchange->generatePreMasterSecret($version);
        
        // 验证长度为48字节（2字节版本号 + 46字节随机数据）
        $this->assertEquals(48, strlen($preMasterSecret));
        
        // 验证前两个字节是版本号
        $this->assertEquals($version, unpack('n', substr($preMasterSecret, 0, 2))[1]);
    }
    
    /**
     * 测试加密预主密钥
     */
    public function testEncryptPreMasterSecret(): void
    {
        $this->markTestSkipped('跳过需要OpenSSL密钥生成的测试');
        
        // 生成测试用RSA密钥对
        $keyPair = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        
        // 提取公钥
        $keyDetails = openssl_pkey_get_details($keyPair);
        $publicKey = $keyDetails['key'];
        
        // 提取私钥
        openssl_pkey_export($keyPair, $privateKey);
        
        $exchange = new RSAKeyExchange();
        $exchange->setServerPublicKey($publicKey);
        
        // 生成预主密钥
        $preMasterSecret = $exchange->generatePreMasterSecret(0x0303);
        
        // 加密预主密钥
        $encryptedPreMasterSecret = $exchange->encryptPreMasterSecret();
        
        // 验证加密结果不为空
        $this->assertNotEmpty($encryptedPreMasterSecret);
        
        // 验证加密结果与原始预主密钥不同
        $this->assertNotEquals($preMasterSecret, $encryptedPreMasterSecret);
        
        // 使用私钥解密验证
        $decrypted = '';
        $result = openssl_private_decrypt($encryptedPreMasterSecret, $decrypted, $privateKey, OPENSSL_PKCS1_PADDING);
        
        $this->assertTrue($result);
        $this->assertEquals($preMasterSecret, $decrypted);
    }
    
    /**
     * 测试解密预主密钥
     */
    public function testDecryptPreMasterSecret(): void
    {
        $this->markTestSkipped('跳过需要OpenSSL密钥生成的测试');
        
        // 生成测试用RSA密钥对
        $keyPair = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        
        // 提取公钥
        $keyDetails = openssl_pkey_get_details($keyPair);
        $publicKey = $keyDetails['key'];
        
        // 提取私钥
        openssl_pkey_export($keyPair, $privateKey);
        
        $exchange = new RSAKeyExchange();
        $exchange->setServerPublicKey($publicKey);
        
        // 生成预主密钥
        $originalPreMasterSecret = $exchange->generatePreMasterSecret(0x0303);
        
        // 加密预主密钥
        $encryptedPreMasterSecret = $exchange->encryptPreMasterSecret();
        
        // 测试解密
        $decryptedPreMasterSecret = $exchange->decryptPreMasterSecret($encryptedPreMasterSecret, $privateKey);
        
        // 验证解密结果与原始预主密钥相同
        $this->assertEquals($originalPreMasterSecret, $decryptedPreMasterSecret);
        $this->assertEquals($originalPreMasterSecret, $exchange->getPreMasterSecret());
    }
    
    /**
     * 测试没有生成预主密钥时加密抛出异常
     */
    public function testEncryptWithoutPreMasterSecretThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Pre-master secret not generated');
        
        $exchange = new RSAKeyExchange();
        $exchange->setServerPublicKey("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqUm\ntYTNPYQGQykP0GCc\n1SecN4PXgbgokH+NE5oK3M/hCYV2FfvtgcuaKrWrLzN3IFS\nFKWXm6UZ5AhvBnQQP\nxLKHx3Pu4Q==\n-----END PUBLIC KEY-----");
        $exchange->encryptPreMasterSecret();
    }
    
    /**
     * 测试没有设置服务器公钥时加密抛出异常
     */
    public function testEncryptWithoutServerPublicKeyThrowsException(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Server public key not set');
        
        $exchange = new RSAKeyExchange();
        $exchange->generatePreMasterSecret(0x0303);
        $exchange->encryptPreMasterSecret();
    }
} 
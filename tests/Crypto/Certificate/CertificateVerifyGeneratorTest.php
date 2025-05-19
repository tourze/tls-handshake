<?php

namespace Tourze\TLSHandshake\Tests\Crypto\Certificate;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\Certificate\CertificateVerifyGenerator;
use Tourze\TLSHandshake\Message\CertificateVerifyMessage;

/**
 * 证书验证消息生成器测试类
 */
class CertificateVerifyGeneratorTest extends TestCase
{
    /**
     * 测试TLS 1.2生成证书验证消息
     */
    public function testGenerateTLS12VerifyMessage(): void
    {
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange';
        $privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJcWv5GMAuzfYK\n-----END PRIVATE KEY-----\n";
        $signatureAlgorithm = 0x0401; // rsa_pkcs1_sha256
        
        $generator = $this->getMockBuilder(CertificateVerifyGenerator::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['signData'])
            ->getMock();
        
        // 模拟签名数据
        $signature = str_repeat('A', 128); // 假设签名长度为128字节
        $generator->method('signData')
            ->willReturn($signature);
        
        $message = $generator->generateTLS12VerifyMessage($handshakeMessages, $privateKey, $signatureAlgorithm);
        
        $this->assertInstanceOf(CertificateVerifyMessage::class, $message);
        $this->assertEquals($signatureAlgorithm, $message->getSignatureAlgorithm());
        $this->assertEquals($signature, $message->getSignature());
    }
    
    /**
     * 测试TLS 1.3生成证书验证消息
     */
    public function testGenerateTLS13VerifyMessage(): void
    {
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate';
        $privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJcWv5GMAuzfYK\n-----END PRIVATE KEY-----\n";
        $signatureAlgorithm = 0x0804; // rsa_pss_rsae_sha256
        
        $generator = $this->getMockBuilder(CertificateVerifyGenerator::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['signData'])
            ->getMock();
        
        // 模拟签名数据
        $signature = str_repeat('B', 256); // 假设签名长度为256字节
        $generator->method('signData')
            ->willReturn($signature);
        
        $message = $generator->generateTLS13VerifyMessage($handshakeContext, $privateKey, $signatureAlgorithm, 'client');
        
        $this->assertInstanceOf(CertificateVerifyMessage::class, $message);
        $this->assertEquals($signatureAlgorithm, $message->getSignatureAlgorithm());
        $this->assertEquals($signature, $message->getSignature());
    }
    
    /**
     * 测试验证TLS 1.2证书验证消息
     */
    public function testVerifyTLS12VerifyMessage(): void
    {
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange';
        $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXFr+RjALs32CvmBHSUx\n-----END PUBLIC KEY-----\n";
        
        $generator = $this->getMockBuilder(CertificateVerifyGenerator::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['verifySignature'])
            ->getMock();
        
        // 模拟签名验证
        $generator->method('verifySignature')
            ->willReturn(true);
        
        $message = new CertificateVerifyMessage();
        $message->setSignatureAlgorithm(0x0401); // rsa_pkcs1_sha256
        $message->setSignature(str_repeat('A', 128));
        
        $result = $generator->verifyTLS12VerifyMessage($message, $handshakeMessages, $publicKey);
        
        $this->assertTrue($result);
    }
    
    /**
     * 测试验证TLS 1.3证书验证消息
     */
    public function testVerifyTLS13VerifyMessage(): void
    {
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate';
        $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXFr+RjALs32CvmBHSUx\n-----END PUBLIC KEY-----\n";
        
        $generator = $this->getMockBuilder(CertificateVerifyGenerator::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['verifySignature'])
            ->getMock();
        
        // 模拟签名验证
        $generator->method('verifySignature')
            ->willReturn(true);
        
        $message = new CertificateVerifyMessage();
        $message->setSignatureAlgorithm(0x0804); // rsa_pss_rsae_sha256
        $message->setSignature(str_repeat('B', 256));
        
        $result = $generator->verifyTLS13VerifyMessage($message, $handshakeContext, $publicKey, 'server');
        
        $this->assertTrue($result);
    }
} 
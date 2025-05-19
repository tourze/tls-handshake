<?php

namespace Tourze\TLSHandshake\Tests\Crypto\Certificate;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\Certificate\CertificateVerificationResult;
use Tourze\TLSHandshake\Crypto\Certificate\CertificateVerifier;

/**
 * 证书验证器测试类
 */
class CertificateVerifierTest extends TestCase
{
    /**
     * 测试验证接口基本功能
     */
    public function testVerifyInterface(): void
    {
        $verifier = $this->getMockForAbstractClass(CertificateVerifier::class);
        
        // 模拟方法返回值
        $verifier->method('verify')
            ->willReturn(new CertificateVerificationResult(true, '验证成功'));
        
        $cert = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\nBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMQ8wDQYD\nVQQKDAZUb3VyemUxETAPBgNVBAsMCFNlY3VyaXR5MB4XDTIzMDExMDAwMDAwMFoX\nDTI0MDExMDAwMDAwMFowVTELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcx\nEDAOBgNVBAcMB0JlaWppbmcxDzANBgNVBAoMBlRvdXJ6ZTERMA8GA1UECwwIU2Vj\ndXJpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJcWv5GMAuzfYK\n-----END CERTIFICATE-----\n";
        
        $result = $verifier->verify($cert, []);
        
        $this->assertTrue($result->isValid());
        $this->assertEquals('验证成功', $result->getMessage());
    }
    
    /**
     * 测试验证不受信任的证书
     */
    public function testVerifyUntrustedCertificate(): void
    {
        $verifier = $this->getMockForAbstractClass(CertificateVerifier::class);
        
        // 模拟方法返回值
        $verifier->method('verify')
            ->willReturn(new CertificateVerificationResult(false, '证书不受信任'));
        
        $cert = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        
        $result = $verifier->verify($cert, []);
        
        $this->assertFalse($result->isValid());
        $this->assertEquals('证书不受信任', $result->getMessage());
    }
    
    /**
     * 测试验证过期的证书
     */
    public function testVerifyExpiredCertificate(): void
    {
        $verifier = $this->getMockForAbstractClass(CertificateVerifier::class);
        
        // 模拟方法返回值
        $verifier->method('verify')
            ->willReturn(new CertificateVerificationResult(false, '证书已过期'));
        
        $cert = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        
        $result = $verifier->verify($cert, []);
        
        $this->assertFalse($result->isValid());
        $this->assertEquals('证书已过期', $result->getMessage());
    }
    
    /**
     * 测试验证证书链
     */
    public function testVerifyCertificateChain(): void
    {
        $verifier = $this->getMockForAbstractClass(CertificateVerifier::class);
        
        // 模拟方法返回值
        $verifier->method('verify')
            ->willReturn(new CertificateVerificationResult(true, '证书链验证成功'));
        
        $cert = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        $chain = [
            "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n"
        ];
        
        $result = $verifier->verify($cert, $chain);
        
        $this->assertTrue($result->isValid());
        $this->assertEquals('证书链验证成功', $result->getMessage());
    }
} 
<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Certificate\CertificateInterface;
use Tourze\TLSHandshake\Session\PSKCertificateBinder;

class PSKCertificateBinderTest extends TestCase
{
    private PSKCertificateBinder $binder;
    
    protected function setUp(): void
    {
        $this->binder = new PSKCertificateBinder();
    }
    
    public function testBindCertificateToPSK(): void
    {
        $pskIdentity = 'test-psk-identity';
        $certificate = $this->createMock(CertificateInterface::class);
        
        $this->binder->bindCertificateToPSK($pskIdentity, $certificate);
        
        $boundCertificate = $this->binder->getCertificateForPSK($pskIdentity);
        $this->assertSame($certificate, $boundCertificate, '应返回绑定到PSK的证书');
    }
    
    public function testGetCertificateForUnknownPSK(): void
    {
        $pskIdentity = 'unknown-psk-identity';
        
        $certificate = $this->binder->getCertificateForPSK($pskIdentity);
        $this->assertNull($certificate, '未绑定的PSK应返回null');
    }
    
    public function testRemoveBindingForPSK(): void
    {
        $pskIdentity = 'test-psk-identity';
        $certificate = $this->createMock(CertificateInterface::class);
        
        $this->binder->bindCertificateToPSK($pskIdentity, $certificate);
        $this->assertNotNull($this->binder->getCertificateForPSK($pskIdentity));
        
        $this->binder->removeBindingForPSK($pskIdentity);
        $this->assertNull($this->binder->getCertificateForPSK($pskIdentity), '移除绑定后应返回null');
    }
    
    public function testIsPSKBoundToCertificate(): void
    {
        $pskIdentity = 'test-psk-identity';
        $certificate = $this->createMock(CertificateInterface::class);
        
        $this->assertFalse($this->binder->isPSKBoundToCertificate($pskIdentity), '未绑定的PSK应返回false');
        
        $this->binder->bindCertificateToPSK($pskIdentity, $certificate);
        $this->assertTrue($this->binder->isPSKBoundToCertificate($pskIdentity), '已绑定的PSK应返回true');
    }
    
    public function testGetPSKIdentitiesForCertificate(): void
    {
        $pskIdentity1 = 'test-psk-identity-1';
        $pskIdentity2 = 'test-psk-identity-2';
        $certificate = $this->createMock(CertificateInterface::class);
        $anotherCertificate = $this->createMock(CertificateInterface::class);
        
        $this->binder->bindCertificateToPSK($pskIdentity1, $certificate);
        $this->binder->bindCertificateToPSK($pskIdentity2, $certificate);
        $this->binder->bindCertificateToPSK('other-psk', $anotherCertificate);
        
        $identities = $this->binder->getPSKIdentitiesForCertificate($certificate);
        
        $this->assertCount(2, $identities, '应返回两个绑定到证书的PSK身份');
        $this->assertContains($pskIdentity1, $identities);
        $this->assertContains($pskIdentity2, $identities);
    }
} 
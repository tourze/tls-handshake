<?php

namespace Tourze\TLSHandshake\Tests\Certificate;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Certificate\CertificateVerificationResult;

class CertificateVerificationResultTest extends TestCase
{
    public function testCanCreateWithValidState(): void
    {
        $result = new CertificateVerificationResult(true, '证书验证通过');
        
        $this->assertTrue($result->isValid());
        $this->assertEquals('证书验证通过', $result->getMessage());
    }
    
    public function testCanCreateWithInvalidState(): void
    {
        $result = new CertificateVerificationResult(false, '证书已过期');
        
        $this->assertFalse($result->isValid());
        $this->assertEquals('证书已过期', $result->getMessage());
    }
    
    public function testCanSwitchToInvalidState(): void
    {
        $result = new CertificateVerificationResult(true, '证书验证通过');
        $invalidResult = $result->withError('证书签名无效');
        
        // 原对象保持不变
        $this->assertTrue($result->isValid());
        $this->assertEquals('证书验证通过', $result->getMessage());
        
        // 新对象状态已更改
        $this->assertFalse($invalidResult->isValid());
        $this->assertEquals('证书签名无效', $invalidResult->getMessage());
    }
    
    public function testCanCreateEmptyMessage(): void
    {
        $result = new CertificateVerificationResult(true);
        
        $this->assertTrue($result->isValid());
        $this->assertEquals('', $result->getMessage());
    }
} 
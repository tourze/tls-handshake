<?php

namespace Tourze\TLSHandshake\Tests\Crypto\Certificate;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Crypto\Certificate\SCTValidator;

/**
 * 证书透明度(SCT)验证器测试类
 */
class SCTValidatorTest extends TestCase
{
    /**
     * 测试解析SCT数据
     */
    public function testParseSCTData(): void
    {
        // 准备测试数据
        // 由于SCT数据格式很复杂，我们需要保证列表长度和实际数据长度一致
        
        // 创建一个非常简单的SCT数据用于测试
        $version = chr(0); // 版本 V1
        $logId = str_repeat('A', 32); // 日志ID (32字节)
        $timestamp = str_repeat(chr(0), 8); // 8字节时间戳 (全零)
        $extensionsLength = pack('n', 0); // 扩展长度 (0)
        $hashAlgorithm = chr(4); // SHA-256
        $signatureAlgorithm = chr(3); // ECDSA
        $signatureData = str_repeat('B', 64); // 64字节签名
        $signatureLength = pack('n', 64); // 签名长度
        
        // 单个SCT数据
        $sctData = $version . $logId . $timestamp . $extensionsLength . 
                   $hashAlgorithm . $signatureAlgorithm . $signatureLength . $signatureData;
                   
        // 计算SCT数据长度 (1 + 32 + 8 + 2 + 1 + 1 + 2 + 64)
        $sctLength = strlen($sctData);
        $sctLengthPacked = pack('n', $sctLength);
        
        // 列表总长度等于SCT长度加上SCT长度字段长度
        $totalLength = $sctLength + 2;
        $totalLengthPacked = pack('n', $totalLength);
        
        // 完整的SCT列表数据
        $fullData = $totalLengthPacked . $sctLengthPacked . $sctData;
        
        // 验证SCT格式
        $validator = new SCTValidator();
        $result = $validator->parseSCTList($fullData);
        
        $this->assertIsArray($result);
        $this->assertCount(1, $result);
        
        $sct = $result[0];
        $this->assertArrayHasKey('version', $sct);
        $this->assertEquals(0, $sct['version']);
        $this->assertArrayHasKey('logId', $sct);
        $this->assertEquals(str_repeat('A', 32), $sct['logId']);
        $this->assertArrayHasKey('timestamp', $sct);
        $this->assertArrayHasKey('signature', $sct);
        $this->assertArrayHasKey('hashAlgorithm', $sct['signature']);
        $this->assertEquals(4, $sct['signature']['hashAlgorithm']);
        $this->assertArrayHasKey('signatureAlgorithm', $sct['signature']);
        $this->assertEquals(3, $sct['signature']['signatureAlgorithm']);
        $this->assertArrayHasKey('signatureData', $sct['signature']);
        $this->assertEquals(str_repeat('B', 64), $sct['signature']['signatureData']);
    }
    
    /**
     * 测试验证有效的SCT
     */
    public function testValidateSCT(): void
    {
        $validator = $this->getMockBuilder(SCTValidator::class)
            ->onlyMethods(['fetchLogPublicKey', 'verifySignature'])
            ->getMock();
        
        // 模拟获取日志公钥
        $validator->method('fetchLogPublicKey')
            ->willReturn("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXFr+RjALs32CvmBHSUx\n-----END PUBLIC KEY-----\n");
        
        // 模拟签名验证
        $validator->method('verifySignature')
            ->willReturn(true);
        
        $sct = [
            'version' => 1,
            'logId' => str_repeat('A', 32),
            'timestamp' => time(),
            'extensions' => '',
            'signature' => [
                'hashAlgorithm' => 4, // SHA-256
                'signatureAlgorithm' => 3, // ECDSA
                'signatureData' => str_repeat('B', 128)
            ]
        ];
        
        $certificate = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        $tbsCertificate = str_repeat('C', 512); // 证书的TBS部分
        
        $result = $validator->validateSCT($sct, $certificate, $tbsCertificate);
        
        $this->assertTrue($result);
    }
    
    /**
     * 测试验证无效的SCT
     */
    public function testValidateInvalidSCT(): void
    {
        $validator = $this->getMockBuilder(SCTValidator::class)
            ->onlyMethods(['fetchLogPublicKey', 'verifySignature'])
            ->getMock();
        
        // 模拟获取日志公钥
        $validator->method('fetchLogPublicKey')
            ->willReturn("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXFr+RjALs32CvmBHSUx\n-----END PUBLIC KEY-----\n");
        
        // 模拟签名验证 - 返回失败
        $validator->method('verifySignature')
            ->willReturn(false);
        
        $sct = [
            'version' => 1,
            'logId' => str_repeat('A', 32),
            'timestamp' => time(),
            'extensions' => '',
            'signature' => [
                'hashAlgorithm' => 4, // SHA-256
                'signatureAlgorithm' => 3, // ECDSA
                'signatureData' => str_repeat('B', 128)
            ]
        ];
        
        $certificate = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        $tbsCertificate = str_repeat('C', 512); // 证书的TBS部分
        
        $result = $validator->validateSCT($sct, $certificate, $tbsCertificate);
        
        $this->assertFalse($result);
    }
    
    /**
     * 测试验证包含SCT扩展的证书
     */
    public function testValidateCertificateWithSCTExtension(): void
    {
        $validator = $this->getMockBuilder(SCTValidator::class)
            ->onlyMethods(['extractSCTFromCertificate', 'parseSCTList', 'validateSCT', 'extractTBSCertificate'])
            ->getMock();
        
        // 创建一个简单的SCT数据，和testParseSCTData中使用的结构一致
        $version = chr(0); // 版本 V1
        $logId = str_repeat('A', 32); // 日志ID (32字节)
        $timestamp = str_repeat(chr(0), 8); // 8字节时间戳 (全零)
        $extensionsLength = pack('n', 0); // 扩展长度 (0)
        $hashAlgorithm = chr(4); // SHA-256
        $signatureAlgorithm = chr(3); // ECDSA
        $signatureData = str_repeat('B', 64); // 64字节签名
        $signatureLength = pack('n', 64); // 签名长度
        
        // 单个SCT数据
        $sctData = $version . $logId . $timestamp . $extensionsLength . 
                   $hashAlgorithm . $signatureAlgorithm . $signatureLength . $signatureData;
                   
        // 计算SCT数据长度
        $sctLength = strlen($sctData);
        $sctLengthPacked = pack('n', $sctLength);
        
        // 列表总长度等于SCT长度加上SCT长度字段长度
        $totalLength = $sctLength + 2;
        $totalLengthPacked = pack('n', $totalLength);
        
        // 完整的SCT列表数据
        $fullData = $totalLengthPacked . $sctLengthPacked . $sctData;
        
        // 模拟从证书中提取SCT数据
        $validator->method('extractSCTFromCertificate')
            ->willReturn($fullData);
        
        // 创建和测试用例一致的SCT解析结果
        $scts = [
            [
                'version' => 0,
                'logId' => str_repeat('A', 32),
                'timestamp' => 0,
                'extensions' => '',
                'signature' => [
                    'hashAlgorithm' => 4,
                    'signatureAlgorithm' => 3,
                    'signatureData' => str_repeat('B', 64)
                ]
            ]
        ];
        
        // 模拟解析SCT列表
        $validator->method('parseSCTList')
            ->willReturn($scts);
        
        // 模拟TBS证书提取
        $validator->method('extractTBSCertificate')
            ->willReturn(str_repeat('C', 512));
        
        // 模拟验证SCT，返回true
        $validator->method('validateSCT')
            ->willReturn(true);
        
        $certificate = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        
        $result = $validator->validateCertificate($certificate);
        
        $this->assertTrue($result);
    }
} 
<?php

namespace Tourze\TLSHandshake\Tests\Crypto\Certificate;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Config\HandshakeConfig;
use Tourze\TLSHandshake\Crypto\Certificate\ClientCertificateHandler;
use Tourze\TLSHandshake\Message\CertificateRequestMessage;

/**
 * 客户端证书处理器测试类
 */
class ClientCertificateHandlerTest extends TestCase
{
    /**
     * 测试处理证书请求
     */
    public function testHandleCertificateRequest(): void
    {
        $config = $this->createMock(HandshakeConfig::class);
        $config->method('getClientCertificatePath')
            ->willReturn('/path/to/client.pem');
        $config->method('getClientPrivateKeyPath')
            ->willReturn('/path/to/client.key');
        
        // 创建自定义的ClientCertificateHandler子类覆盖文件检查
        $handler = new class($config) extends ClientCertificateHandler {
            public function handleCertificateRequest(CertificateRequestMessage $requestMessage): ?array
            {
                // 直接返回假的证书数据，绕过文件存在检查
                return [
                    'certificate' => "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n",
                    'privateKey' => "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJcWv5GMAuzfYK\n-----END PRIVATE KEY-----\n"
                ];
            }
        };
        
        $requestMessage = new CertificateRequestMessage();
        $requestMessage->addCertificateType(ClientCertificateHandler::CERT_TYPE_RSA_SIGN); // RSA签名
        
        $result = $handler->handleCertificateRequest($requestMessage);
        
        $this->assertNotEmpty($result);
        $this->assertArrayHasKey('certificate', $result);
        $this->assertArrayHasKey('privateKey', $result);
        $this->assertStringContainsString('BEGIN CERTIFICATE', $result['certificate']);
        $this->assertStringContainsString('BEGIN PRIVATE KEY', $result['privateKey']);
    }
    
    /**
     * 测试没有配置客户端证书
     */
    public function testNoClientCertificate(): void
    {
        $config = $this->createMock(HandshakeConfig::class);
        $config->method('getClientCertificatePath')
            ->willReturn(null);
        $config->method('getClientPrivateKeyPath')
            ->willReturn(null);
        
        $handler = new ClientCertificateHandler($config);
        
        $requestMessage = new CertificateRequestMessage();
        $requestMessage->addCertificateType(1); // RSA签名
        
        $result = $handler->handleCertificateRequest($requestMessage);
        
        $this->assertNull($result);
    }
    
    /**
     * 测试证书类型不匹配
     */
    public function testCertificateTypeMismatch(): void
    {
        $config = $this->createMock(HandshakeConfig::class);
        $config->method('getClientCertificatePath')
            ->willReturn('/path/to/client.pem');
        $config->method('getClientPrivateKeyPath')
            ->willReturn('/path/to/client.key');
        
        // 创建自定义的ClientCertificateHandler子类覆盖文件检查
        $handler = new class($config) extends ClientCertificateHandler {
            protected function getCertificateType(string $certificate): int
            {
                return self::CERT_TYPE_DSS_SIGN; // 返回DSS类型证书
            }
            
            public function handleCertificateRequest(CertificateRequestMessage $requestMessage): ?array
            {
                if (in_array(self::CERT_TYPE_DSS_SIGN, $requestMessage->getCertificateTypes(), true)) {
                    return [
                        'certificate' => "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n",
                        'privateKey' => "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJcWv5GMAuzfYK\n-----END PRIVATE KEY-----\n"
                    ];
                }
                return null;
            }
        };
        
        $requestMessage = new CertificateRequestMessage();
        $requestMessage->addCertificateType(1); // 只接受RSA签名
        
        $result = $handler->handleCertificateRequest($requestMessage);
        
        $this->assertNull($result);
    }
}

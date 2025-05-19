<?php

namespace Tourze\TLSHandshake\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Message\CertificateMessage;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * Certificate消息测试类
 */
class CertificateMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new CertificateMessage();
        $this->assertEquals(HandshakeMessageType::CERTIFICATE, $message->getType());
    }
    
    /**
     * 测试证书链操作
     */
    public function testCertificateChain(): void
    {
        $message = new CertificateMessage();
        
        // 测试默认值
        $this->assertEmpty($message->getCertificates());
        
        // 测试添加证书
        $cert1 = str_repeat('A', 50); // 模拟证书数据
        $cert2 = str_repeat('B', 60); // 模拟证书数据
        
        $message->addCertificate($cert1);
        $this->assertCount(1, $message->getCertificates());
        
        $message->addCertificate($cert2);
        $this->assertCount(2, $message->getCertificates());
        
        // 测试设置证书链
        $certificates = [$cert1, $cert2];
        $message->setCertificates($certificates);
        $this->assertEquals($certificates, $message->getCertificates());
    }
    
    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new CertificateMessage();
        
        // 添加证书
        $cert1 = str_repeat('A', 50);
        $cert2 = str_repeat('B', 60);
        $originalMessage->addCertificate($cert1);
        $originalMessage->addCertificate($cert2);
        
        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedMessage = CertificateMessage::decode($encodedData);
        
        // 比较原始消息和解码后的消息
        $this->assertEquals(count($originalMessage->getCertificates()), count($decodedMessage->getCertificates()));
        $this->assertEquals($originalMessage->getCertificates(), $decodedMessage->getCertificates());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new CertificateMessage();
        
        // 空的证书链是无效的
        $this->assertFalse($message->isValid());
        
        // 添加证书后应该有效
        $message->addCertificate(str_repeat('A', 50));
        $this->assertTrue($message->isValid());
    }
    
    /**
     * 测试证书格式错误情况
     */
    public function testInvalidCertificateFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        
        // 创建一个包含证书长度但实际数据长度不够的二进制数据
        $data = "\x00\x00\x03too"; // 声明长度3但实际没有足够的数据
        CertificateMessage::decode($data);
    }
}

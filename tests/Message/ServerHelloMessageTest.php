<?php

namespace Tourze\TLSHandshake\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Message\ServerHelloMessage;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * ServerHello消息测试类
 */
class ServerHelloMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new ServerHelloMessage();
        $this->assertEquals(HandshakeMessageType::SERVER_HELLO, $message->getType());
    }
    
    /**
     * 测试设置和获取TLS版本
     */
    public function testVersion(): void
    {
        $message = new ServerHelloMessage();
        
        // 测试默认值
        $this->assertEquals(0x0303, $message->getVersion()); // TLS 1.2
        
        // 测试设置值
        $message->setVersion(0x0304); // TLS 1.3
        $this->assertEquals(0x0304, $message->getVersion());
    }
    
    /**
     * 测试随机数生成
     */
    public function testRandom(): void
    {
        $message = new ServerHelloMessage();
        
        // 测试随机数长度
        $this->assertEquals(32, strlen($message->getRandom()));
        
        // 测试设置自定义随机数
        $customRandom = str_repeat('B', 32);
        $message->setRandom($customRandom);
        $this->assertEquals($customRandom, $message->getRandom());
    }
    
    /**
     * 测试会话ID操作
     */
    public function testSessionId(): void
    {
        $message = new ServerHelloMessage();
        
        // 测试默认值
        $this->assertEquals('', $message->getSessionId());
        
        // 测试设置会话ID
        $sessionId = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $message->setSessionId($sessionId);
        $this->assertEquals($sessionId, $message->getSessionId());
    }
    
    /**
     * 测试密码套件操作
     */
    public function testCipherSuite(): void
    {
        $message = new ServerHelloMessage();
        
        // 测试默认值
        $this->assertEquals(0, $message->getCipherSuite());
        
        // 测试设置密码套件
        $cipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256
        $message->setCipherSuite($cipherSuite);
        $this->assertEquals($cipherSuite, $message->getCipherSuite());
    }
    
    /**
     * 测试压缩方法操作
     */
    public function testCompressionMethod(): void
    {
        $message = new ServerHelloMessage();
        
        // 测试默认值 (应该只有null压缩方法0)
        $this->assertEquals(0, $message->getCompressionMethod());
        
        // 测试设置压缩方法
        $compressionMethod = 1; // DEFLATE
        $message->setCompressionMethod($compressionMethod);
        $this->assertEquals($compressionMethod, $message->getCompressionMethod());
    }
    
    /**
     * 测试扩展操作
     */
    public function testExtensions(): void
    {
        $message = new ServerHelloMessage();
        
        // 测试默认值
        $this->assertEmpty($message->getExtensions());
        
        // 测试添加扩展
        $message->addExtension(0x000a, hex2bin('0001002302')); // supported_groups 扩展
        $this->assertArrayHasKey(0x000a, $message->getExtensions());
        
        // 测试设置扩展
        $extensions = [
            0x000a => hex2bin('0001002302'),
            0x000b => hex2bin('010203'), 
        ];
        $message->setExtensions($extensions);
        $this->assertEquals($extensions, $message->getExtensions());
    }
    
    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new ServerHelloMessage();
        $originalMessage->setVersion(0x0303); // TLS 1.2
        $originalMessage->setRandom(str_repeat('B', 32));
        $originalMessage->setSessionId(hex2bin('0102030405060708090a0b0c0d0e0f10'));
        $originalMessage->setCipherSuite(0x1301); // TLS_AES_128_GCM_SHA256
        $originalMessage->setCompressionMethod(0); // null compression
        $originalMessage->addExtension(0x000a, hex2bin('0001002302'));
        
        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedMessage = ServerHelloMessage::decode($encodedData);
        
        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getVersion(), $decodedMessage->getVersion());
        $this->assertEquals($originalMessage->getRandom(), $decodedMessage->getRandom());
        $this->assertEquals($originalMessage->getSessionId(), $decodedMessage->getSessionId());
        $this->assertEquals($originalMessage->getCipherSuite(), $decodedMessage->getCipherSuite());
        $this->assertEquals($originalMessage->getCompressionMethod(), $decodedMessage->getCompressionMethod());
        $this->assertEquals($originalMessage->getExtensions(), $decodedMessage->getExtensions());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new ServerHelloMessage();
        $message->setCipherSuite(0x1301); // 设置有效的密码套件
        $this->assertTrue($message->isValid());
        
        // 测试无效情况
        $invalidMessage = new ServerHelloMessage();
        $invalidMessage->setCipherSuite(0); // 密码套件为0是无效的
        $this->assertFalse($invalidMessage->isValid());
    }
} 
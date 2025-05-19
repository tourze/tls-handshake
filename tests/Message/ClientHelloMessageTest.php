<?php

namespace Tourze\TLSHandshake\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Message\ClientHelloMessage;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * ClientHello消息测试类
 */
class ClientHelloMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new ClientHelloMessage();
        $this->assertEquals(HandshakeMessageType::CLIENT_HELLO, $message->getType());
    }
    
    /**
     * 测试设置和获取TLS版本
     */
    public function testVersion(): void
    {
        $message = new ClientHelloMessage();
        
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
        $message = new ClientHelloMessage();
        
        // 测试随机数长度
        $this->assertEquals(32, strlen($message->getRandom()));
        
        // 测试设置自定义随机数
        $customRandom = str_repeat('A', 32);
        $message->setRandom($customRandom);
        $this->assertEquals($customRandom, $message->getRandom());
    }
    
    /**
     * 测试会话ID操作
     */
    public function testSessionId(): void
    {
        $message = new ClientHelloMessage();
        
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
    public function testCipherSuites(): void
    {
        $message = new ClientHelloMessage();
        
        // 测试默认值
        $this->assertNotEmpty($message->getCipherSuites());
        
        // 测试设置密码套件
        $cipherSuites = [0x1301, 0x1302, 0x1303]; // TLS 1.3 推荐套件
        $message->setCipherSuites($cipherSuites);
        $this->assertEquals($cipherSuites, $message->getCipherSuites());
    }
    
    /**
     * 测试压缩方法操作
     */
    public function testCompressionMethods(): void
    {
        $message = new ClientHelloMessage();
        
        // 测试默认值 (应该只有null压缩方法0)
        $this->assertEquals([0], $message->getCompressionMethods());
        
        // 测试设置压缩方法
        $compressionMethods = [0, 1]; // null和DEFLATE
        $message->setCompressionMethods($compressionMethods);
        $this->assertEquals($compressionMethods, $message->getCompressionMethods());
    }
    
    /**
     * 测试扩展操作
     */
    public function testExtensions(): void
    {
        $message = new ClientHelloMessage();
        
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
        $originalMessage = new ClientHelloMessage();
        $originalMessage->setVersion(0x0303); // TLS 1.2
        $originalMessage->setRandom(str_repeat('A', 32));
        $originalMessage->setSessionId(hex2bin('0102030405060708090a0b0c0d0e0f10'));
        $originalMessage->setCipherSuites([0x1301, 0x1302, 0x1303]);
        $originalMessage->setCompressionMethods([0]);
        $originalMessage->addExtension(0x000a, hex2bin('0001002302'));
        
        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedMessage = ClientHelloMessage::decode($encodedData);
        
        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getVersion(), $decodedMessage->getVersion());
        $this->assertEquals($originalMessage->getRandom(), $decodedMessage->getRandom());
        $this->assertEquals($originalMessage->getSessionId(), $decodedMessage->getSessionId());
        $this->assertEquals($originalMessage->getCipherSuites(), $decodedMessage->getCipherSuites());
        $this->assertEquals($originalMessage->getCompressionMethods(), $decodedMessage->getCompressionMethods());
        $this->assertEquals($originalMessage->getExtensions(), $decodedMessage->getExtensions());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new ClientHelloMessage();
        $this->assertTrue($message->isValid());
        
        // 测试无效情况
        $invalidMessage = new ClientHelloMessage();
        $invalidMessage->setCipherSuites([]); // 没有密码套件是无效的
        $this->assertFalse($invalidMessage->isValid());
    }
}

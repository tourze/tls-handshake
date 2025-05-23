<?php

namespace Tourze\TLSHandshake\Tests\Message;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Message\FinishedMessage;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * Finished消息测试类
 */
class FinishedMessageTest extends TestCase
{
    /**
     * 测试消息类型是否正确
     */
    public function testMessageType(): void
    {
        $message = new FinishedMessage();
        $this->assertEquals(HandshakeMessageType::FINISHED, $message->getType());
    }
    
    /**
     * 测试验证数据操作
     */
    public function testVerifyData(): void
    {
        $message = new FinishedMessage();
        
        // 测试默认值
        $this->assertEquals('', $message->getVerifyData());
        
        // 测试设置验证数据
        $verifyData = hex2bin('0102030405060708090a0b0c');
        $message->setVerifyData($verifyData);
        $this->assertEquals($verifyData, $message->getVerifyData());
    }
    
    /**
     * 测试编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalMessage = new FinishedMessage();
        
        // 设置验证数据
        $verifyData = hex2bin('0102030405060708090a0b0c');
        $originalMessage->setVerifyData($verifyData);
        
        // 编码
        $encodedData = $originalMessage->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedMessage = FinishedMessage::decode($encodedData);
        
        // 比较原始消息和解码后的消息
        $this->assertEquals($originalMessage->getVerifyData(), $decodedMessage->getVerifyData());
    }
    
    /**
     * 测试有效性验证
     */
    public function testValidity(): void
    {
        $message = new FinishedMessage();
        
        // 空的验证数据是无效的
        $this->assertFalse($message->isValid());
        
        // 设置验证数据后应该有效
        $message->setVerifyData(hex2bin('0102030405060708090a0b0c'));
        $this->assertTrue($message->isValid());
    }
}

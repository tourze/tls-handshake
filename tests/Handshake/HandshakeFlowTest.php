<?php

namespace Tourze\TLSHandshake\Tests\Handshake;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Handshake\HandshakeFlow;
use Tourze\TLSHandshake\Handshake\HandshakeStage;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

class HandshakeFlowTest extends TestCase
{
    /**
     * 测试握手流程阶段枚举定义
     */
    public function testHandshakeStages()
    {
        $this->assertEquals(1, HandshakeStage::INITIAL->value);
        $this->assertEquals(2, HandshakeStage::NEGOTIATING->value);
        $this->assertEquals(3, HandshakeStage::KEY_EXCHANGE->value);
        $this->assertEquals(4, HandshakeStage::AUTHENTICATION->value);
        $this->assertEquals(5, HandshakeStage::FINISHED->value);
    }
    
    /**
     * 测试基本的流程进度实现
     */
    public function testFlowProgress()
    {
        $flow = new HandshakeFlow();
        
        // 初始阶段
        $this->assertEquals(HandshakeStage::INITIAL, $flow->getCurrentStage());
        
        // 推进阶段
        $flow->advanceToStage(HandshakeStage::NEGOTIATING);
        $this->assertEquals(HandshakeStage::NEGOTIATING, $flow->getCurrentStage());
        
        $flow->advanceToStage(HandshakeStage::KEY_EXCHANGE);
        $this->assertEquals(HandshakeStage::KEY_EXCHANGE, $flow->getCurrentStage());
        
        // 检查是否已经完成特定阶段
        $this->assertTrue($flow->isStageCompleted(HandshakeStage::INITIAL));
        $this->assertTrue($flow->isStageCompleted(HandshakeStage::NEGOTIATING));
        $this->assertFalse($flow->isStageCompleted(HandshakeStage::AUTHENTICATION));
        $this->assertFalse($flow->isStageCompleted(HandshakeStage::FINISHED));
    }
    
    /**
     * 测试阶段对应的消息类型
     */
    public function testStageMessageTypes()
    {
        $flow = new HandshakeFlow();
        
        // 测试初始阶段预期的消息类型
        $initialMessages = $flow->getExpectedMessageTypes(HandshakeStage::INITIAL);
        $this->assertContains(HandshakeMessageType::CLIENT_HELLO, $initialMessages);
        
        // 测试协商阶段预期的消息类型
        $negotiatingMessages = $flow->getExpectedMessageTypes(HandshakeStage::NEGOTIATING);
        $this->assertContains(HandshakeMessageType::SERVER_HELLO, $negotiatingMessages);
    }
}

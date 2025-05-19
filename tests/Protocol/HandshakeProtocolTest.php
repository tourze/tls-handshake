<?php

namespace Tourze\TLSHandshake\Tests\Protocol;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Protocol\HandshakeProtocol;
use Tourze\TLSHandshake\Protocol\HandshakeProtocolInterface;
use Tourze\TLSHandshake\Protocol\HandshakeProtocolState;

class HandshakeProtocolTest extends TestCase
{
    /**
     * 测试接口实现
     */
    public function testInterfaceImplementation()
    {
        $protocol = new HandshakeProtocol();
        $this->assertInstanceOf(HandshakeProtocolInterface::class, $protocol);
    }

    /**
     * 测试握手状态是否按预期变更
     */
    public function testHandshakeStateTransition()
    {
        $protocol = new HandshakeProtocol();
        
        // 握手初始状态为NOT_STARTED
        $this->assertEquals(HandshakeProtocolState::NOT_STARTED, $protocol->getState());
        
        // 开始握手
        $protocol->startHandshake();
        $this->assertEquals(HandshakeProtocolState::IN_PROGRESS, $protocol->getState());
        
        // 完成握手
        $protocol->completeHandshake();
        $this->assertEquals(HandshakeProtocolState::COMPLETED, $protocol->getState());
    }

    /**
     * 测试获取和设置版本
     */
    public function testVersionHandling()
    {
        $protocol = new HandshakeProtocol();
        
        // 默认版本
        $this->assertNull($protocol->getVersion());
        
        // 设置版本
        $protocol->setVersion('TLS 1.2');
        $this->assertEquals('TLS 1.2', $protocol->getVersion());
    }
}

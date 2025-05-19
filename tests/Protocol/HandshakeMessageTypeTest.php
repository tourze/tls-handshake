<?php

namespace Tourze\TLSHandshake\Tests\Protocol;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

class HandshakeMessageTypeTest extends TestCase
{
    /**
     * 测试消息类型枚举值是否正确定义
     */
    public function testMessageTypeEnumValues()
    {
        $this->assertEquals(0, HandshakeMessageType::HELLO_REQUEST->value);
        $this->assertEquals(1, HandshakeMessageType::CLIENT_HELLO->value);
        $this->assertEquals(2, HandshakeMessageType::SERVER_HELLO->value);
        $this->assertEquals(4, HandshakeMessageType::NEW_SESSION_TICKET->value);
        $this->assertEquals(8, HandshakeMessageType::ENCRYPTED_EXTENSIONS->value);
        $this->assertEquals(11, HandshakeMessageType::CERTIFICATE->value);
        $this->assertEquals(12, HandshakeMessageType::SERVER_KEY_EXCHANGE->value);
        $this->assertEquals(13, HandshakeMessageType::CERTIFICATE_REQUEST->value);
        $this->assertEquals(14, HandshakeMessageType::SERVER_HELLO_DONE->value);
        $this->assertEquals(15, HandshakeMessageType::CERTIFICATE_VERIFY->value);
        $this->assertEquals(16, HandshakeMessageType::CLIENT_KEY_EXCHANGE->value);
        $this->assertEquals(20, HandshakeMessageType::FINISHED->value);
    }

    /**
     * 测试消息类型名称是否正确对应
     */
    public function testGetMessageTypeName()
    {
        $this->assertEquals('CLIENT_HELLO', HandshakeMessageType::CLIENT_HELLO->getName());
        $this->assertEquals('SERVER_HELLO', HandshakeMessageType::SERVER_HELLO->getName());
        $this->assertEquals('CERTIFICATE', HandshakeMessageType::CERTIFICATE->getName());
        
        // 测试静态方法
        $this->assertEquals('CLIENT_HELLO', HandshakeMessageType::getMessageTypeName(HandshakeMessageType::CLIENT_HELLO->value));
        $this->assertEquals('Unknown', HandshakeMessageType::getMessageTypeName(99)); // 未知类型
    }
    
    /**
     * 测试tryFrom方法
     */
    public function testTryFrom()
    {
        $this->assertSame(HandshakeMessageType::CLIENT_HELLO, HandshakeMessageType::tryFrom(1));
        $this->assertSame(HandshakeMessageType::SERVER_HELLO, HandshakeMessageType::tryFrom(2));
        $this->assertNull(HandshakeMessageType::tryFrom(99));
    }
}

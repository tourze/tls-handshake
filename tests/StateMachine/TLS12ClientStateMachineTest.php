<?php

namespace Tourze\TLSHandshake\Tests\StateMachine;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;
use Tourze\TLSHandshake\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshake\StateMachine\TLS12ClientStateMachine;

class TLS12ClientStateMachineTest extends TestCase
{
    /**
     * @var TLS12ClientStateMachine
     */
    private TLS12ClientStateMachine $stateMachine;

    /**
     * 设置测试用例
     */
    protected function setUp(): void
    {
        $this->stateMachine = new TLS12ClientStateMachine();
    }

    /**
     * 测试初始化状态
     */
    public function testInitialState()
    {
        $this->assertEquals(HandshakeStateEnum::INITIAL, $this->stateMachine->getCurrentState());
        $this->assertFalse($this->stateMachine->isHandshakeCompleted());
        $this->assertFalse($this->stateMachine->isInErrorState());
    }

    /**
     * 测试完整的TLS 1.2握手流程
     */
    public function testCompleteTLS12Handshake()
    {
        // 初始状态 -> WAIT_SERVER_HELLO (发送CLIENT_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO -> WAIT_CERTIFICATE (接收SERVER_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CERTIFICATE -> WAIT_SERVER_KEY_EXCHANGE (接收CERTIFICATE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_KEY_EXCHANGE -> WAIT_SERVER_HELLO_DONE (接收SERVER_KEY_EXCHANGE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO_DONE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO_DONE -> WAIT_CLIENT_KEY_EXCHANGE (接收SERVER_HELLO_DONE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO_DONE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CLIENT_KEY_EXCHANGE -> WAIT_CHANGE_CIPHER_SPEC (发送CLIENT_KEY_EXCHANGE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 模拟发送CHANGE_CIPHER_SPEC (不是握手消息，但需要转换状态)
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_FINISHED);

        // WAIT_FINISHED -> CONNECTED (接收FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::CONNECTED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 确认握手已完成
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    /**
     * 测试错误处理
     */
    public function testErrorHandling()
    {
        // 初始状态下接收未预期的消息
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::ERROR, $nextState);
        $this->stateMachine->transitionTo($nextState);
        $this->assertTrue($this->stateMachine->isInErrorState());
    }

    /**
     * 测试重置功能
     */
    public function testReset()
    {
        // 先转换到错误状态
        $this->stateMachine->transitionTo(HandshakeStateEnum::ERROR);
        $this->assertTrue($this->stateMachine->isInErrorState());

        // 重置
        $this->stateMachine->reset();
        $this->assertEquals(HandshakeStateEnum::INITIAL, $this->stateMachine->getCurrentState());
        $this->assertFalse($this->stateMachine->isInErrorState());
    }
} 
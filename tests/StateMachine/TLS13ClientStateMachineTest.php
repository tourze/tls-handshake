<?php

namespace Tourze\TLSHandshake\Tests\StateMachine;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;
use Tourze\TLSHandshake\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshake\StateMachine\TLS13ClientStateMachine;

class TLS13ClientStateMachineTest extends TestCase
{
    /**
     * @var TLS13ClientStateMachine
     */
    private TLS13ClientStateMachine $stateMachine;

    /**
     * 设置测试用例
     */
    protected function setUp(): void
    {
        $this->stateMachine = new TLS13ClientStateMachine();
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
     * 测试完整的TLS 1.3握手流程（不包含0-RTT）
     */
    public function testCompleteTLS13Handshake()
    {
        // 初始状态 -> WAIT_SERVER_HELLO (发送CLIENT_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO -> WAIT_ENCRYPTED_EXTENSIONS (接收SERVER_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_ENCRYPTED_EXTENSIONS -> WAIT_CERTIFICATE (接收ENCRYPTED_EXTENSIONS)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::ENCRYPTED_EXTENSIONS);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CERTIFICATE -> WAIT_CERTIFICATE_VERIFY (接收CERTIFICATE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CERTIFICATE_VERIFY -> WAIT_FINISHED (接收CERTIFICATE_VERIFY)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE_VERIFY);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_FINISHED -> WAIT_NEW_SESSION_TICKET (接收FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_NEW_SESSION_TICKET, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_NEW_SESSION_TICKET -> CONNECTED (接收NEW_SESSION_TICKET)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::NEW_SESSION_TICKET);
        $this->assertEquals(HandshakeStateEnum::CONNECTED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 确认握手已完成
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    /**
     * 测试不需要客户端证书的流程
     */
    public function testHandshakeWithoutClientCertificate()
    {
        // 跳到等待加密扩展状态
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS);
        
        // WAIT_ENCRYPTED_EXTENSIONS -> WAIT_CERTIFICATE (接收ENCRYPTED_EXTENSIONS)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::ENCRYPTED_EXTENSIONS);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE, $nextState);
        $this->stateMachine->transitionTo($nextState);
        
        // 直接跳到WAIT_FINISHED(不需要客户端证书，服务器可能跳过证书消息)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_NEW_SESSION_TICKET, $nextState);
        $this->stateMachine->transitionTo($nextState);
    }

    /**
     * 测试PSK恢复模式
     */
    public function testPSKResumeHandshake()
    {
        // 初始状态 -> WAIT_SERVER_HELLO (发送带PSK的CLIENT_HELLO)
        $this->stateMachine->setPSKMode(true);
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO -> WAIT_ENCRYPTED_EXTENSIONS (接收SERVER_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // PSK模式下，服务器可能直接跳到FINISHED，不需要证书
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::ENCRYPTED_EXTENSIONS);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_FINISHED -> WAIT_NEW_SESSION_TICKET (接收FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_NEW_SESSION_TICKET, $nextState);
        $this->stateMachine->transitionTo($nextState);
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
} 
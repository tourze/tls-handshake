<?php

namespace Tourze\TLSHandshake\Tests\StateMachine;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;
use Tourze\TLSHandshake\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshake\StateMachine\TLS13ServerStateMachine;

class TLS13ServerStateMachineTest extends TestCase
{
    /**
     * @var TLS13ServerStateMachine
     */
    private TLS13ServerStateMachine $stateMachine;

    /**
     * 设置测试用例
     */
    protected function setUp(): void
    {
        $this->stateMachine = new TLS13ServerStateMachine();
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
        // 初始状态 -> WAIT_SERVER_HELLO (接收CLIENT_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO -> WAIT_ENCRYPTED_EXTENSIONS (发送SERVER_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_ENCRYPTED_EXTENSIONS -> WAIT_CERTIFICATE (发送ENCRYPTED_EXTENSIONS)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::ENCRYPTED_EXTENSIONS);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CERTIFICATE -> WAIT_CERTIFICATE_VERIFY (发送CERTIFICATE)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CERTIFICATE_VERIFY -> WAIT_FINISHED (发送CERTIFICATE_VERIFY)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE_VERIFY);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_FINISHED -> WAIT_CLIENT_FINISHED (发送FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_CLIENT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_CLIENT_FINISHED -> WAIT_NEW_SESSION_TICKET (接收客户端FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_NEW_SESSION_TICKET, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_NEW_SESSION_TICKET -> CONNECTED (发送NEW_SESSION_TICKET)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::NEW_SESSION_TICKET);
        $this->assertEquals(HandshakeStateEnum::CONNECTED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 确认握手已完成
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    /**
     * 测试PSK模式握手流程
     */
    public function testPSKModeHandshake()
    {
        // 设置PSK模式
        $this->stateMachine->setPSKMode(true);
        
        // 初始状态 -> WAIT_SERVER_HELLO (接收带PSK的CLIENT_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_SERVER_HELLO -> WAIT_ENCRYPTED_EXTENSIONS (发送接受PSK的SERVER_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::SERVER_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // PSK模式下，跳过证书相关步骤
        // WAIT_ENCRYPTED_EXTENSIONS -> WAIT_FINISHED (发送ENCRYPTED_EXTENSIONS)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::ENCRYPTED_EXTENSIONS);
        $this->assertEquals(HandshakeStateEnum::WAIT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // WAIT_FINISHED -> WAIT_CLIENT_FINISHED (发送FINISHED)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_CLIENT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);

        // 收到客户端Finished，握手完成
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::FINISHED);
        $this->assertEquals(HandshakeStateEnum::WAIT_NEW_SESSION_TICKET, $nextState);
        $this->stateMachine->transitionTo($nextState);
    }

    /**
     * 测试要求客户端证书的握手流程
     */
    public function testClientCertificateHandshake()
    {
        // 先到达证书状态
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_CERTIFICATE);
        
        // 要求客户端证书
        $this->stateMachine->setClientCertificateRequired(true);
        
        // WAIT_CERTIFICATE -> WAIT_CERTIFICATE_VERIFY (发送CERTIFICATE和CERTIFICATE_REQUEST)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE_REQUEST);
        $this->assertEquals(HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY, $nextState);
        $this->stateMachine->transitionTo($nextState);
        
        // 继续正常流程
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_FINISHED);
        
        // 进入等待客户端证书状态
        $this->stateMachine->transitionTo(HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE);
        
        // 接收客户端证书，进入验证状态
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE);
        $this->assertEquals(HandshakeStateEnum::WAIT_CLIENT_VERIFY, $nextState);
        $this->stateMachine->transitionTo($nextState);
        
        // 接收客户端证书验证，继续握手流程
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CERTIFICATE_VERIFY);
        $this->assertEquals(HandshakeStateEnum::WAIT_CLIENT_FINISHED, $nextState);
        $this->stateMachine->transitionTo($nextState);
    }

    /**
     * 测试0-RTT早期数据接收
     */
    public function testEarlyDataHandling()
    {
        // 启用0-RTT支持
        $this->stateMachine->setEarlyDataEnabled(true);
        
        // 初始状态 -> WAIT_SERVER_HELLO (接收带早期数据的CLIENT_HELLO)
        $nextState = $this->stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::PROCESS_EARLY_DATA, $nextState);
        $this->stateMachine->transitionTo($nextState);
        
        // 处理早期数据后，继续正常握手流程
        $this->stateMachine->earlyDataProcessed();
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $this->stateMachine->getCurrentState());
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
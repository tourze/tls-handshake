<?php

namespace Tourze\TLSHandshake\Tests\StateMachine;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Protocol\HandshakeMessageType;
use Tourze\TLSHandshake\StateMachine\ClientStateMachine;
use Tourze\TLSHandshake\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshake\StateMachine\ServerStateMachine;

class HandshakeStateMachineTest extends TestCase
{
    /**
     * 测试状态机状态枚举定义
     */
    public function testStateMachineStates()
    {
        $states = [
            HandshakeStateEnum::INITIAL,
            HandshakeStateEnum::WAIT_SERVER_HELLO,
            HandshakeStateEnum::WAIT_CERTIFICATE,
            HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE,
            HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
            HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE,
            HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
            HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
            HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
            HandshakeStateEnum::WAIT_FINISHED,
            HandshakeStateEnum::CONNECTED,
            HandshakeStateEnum::ERROR,
        ];
        
        // 确保所有状态都是HandshakeStateEnum类型
        foreach ($states as $state) {
            $this->assertInstanceOf(HandshakeStateEnum::class, $state);
        }
    }
    
    /**
     * 测试客户端状态机基本功能
     */
    public function testClientStateMachine()
    {
        $stateMachine = new ClientStateMachine();
        
        // 初始状态
        $this->assertEquals(HandshakeStateEnum::INITIAL, $stateMachine->getCurrentState());
        
        // 处理状态转换
        $nextState = $stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $nextState);
        
        // 转换到下一个状态
        $stateMachine->transitionTo($nextState);
        $this->assertEquals(HandshakeStateEnum::WAIT_SERVER_HELLO, $stateMachine->getCurrentState());
    }
    
    /**
     * 测试服务器状态机基本功能
     */
    public function testServerStateMachine()
    {
        $stateMachine = new ServerStateMachine();
        
        // 初始状态
        $this->assertEquals(HandshakeStateEnum::INITIAL, $stateMachine->getCurrentState());
        
        // 处理状态转换
        $nextState = $stateMachine->getNextState(HandshakeMessageType::CLIENT_HELLO);
        $this->assertNotEquals(HandshakeStateEnum::INITIAL, $nextState);
        
        // 转换到下一个状态
        $stateMachine->transitionTo($nextState);
        $this->assertNotEquals(HandshakeStateEnum::INITIAL, $stateMachine->getCurrentState());
    }
    
    /**
     * 测试状态机错误处理
     */
    public function testErrorHandling()
    {
        $stateMachine = new ClientStateMachine();
        
        // 在初始状态下接收未预期的消息
        $nextState = $stateMachine->getNextState(HandshakeMessageType::SERVER_KEY_EXCHANGE);
        $this->assertEquals(HandshakeStateEnum::ERROR, $nextState);
    }
}

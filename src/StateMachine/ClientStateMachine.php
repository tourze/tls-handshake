<?php

namespace Tourze\TLSHandshake\StateMachine;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * 客户端握手状态机实现
 */
class ClientStateMachine extends AbstractHandshakeStateMachine
{
    /**
     * {@inheritdoc}
     */
    protected function initializeStateTransitions(): void
    {
        // 初始状态下，发送ClientHello后等待ServerHello
        $this->stateTransitions[HandshakeStateEnum::INITIAL->value] = [
            HandshakeMessageType::CLIENT_HELLO->value => HandshakeStateEnum::WAIT_SERVER_HELLO,
        ];
        
        // 收到ServerHello后，等待服务器证书
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO->value] = [
            HandshakeMessageType::SERVER_HELLO->value => HandshakeStateEnum::WAIT_CERTIFICATE,
            // TLS 1.3的处理
            HandshakeMessageType::ENCRYPTED_EXTENSIONS->value => HandshakeStateEnum::WAIT_CERTIFICATE,
        ];
        
        // 收到证书后，等待ServerKeyExchange（如果需要）或ServerHelloDone
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE->value] = [
            HandshakeMessageType::CERTIFICATE->value => HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE,
            HandshakeMessageType::SERVER_HELLO_DONE->value => HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
        ];
        
        // 收到ServerKeyExchange后，等待ServerHelloDone
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE->value] = [
            HandshakeMessageType::SERVER_KEY_EXCHANGE->value => HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
            HandshakeMessageType::SERVER_HELLO_DONE->value => HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
        ];
        
        // 收到ServerHelloDone后，发送ClientKeyExchange，然后等待服务器的Finished消息
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO_DONE->value] = [
            HandshakeMessageType::SERVER_HELLO_DONE->value => HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
        ];
        
        // 发送ClientKeyExchange后等待服务器的Finished消息
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE->value] = [
            HandshakeMessageType::CLIENT_KEY_EXCHANGE->value => HandshakeStateEnum::WAIT_FINISHED,
        ];
        
        // 收到服务器Finished消息后，握手完成
        $this->stateTransitions[HandshakeStateEnum::WAIT_FINISHED->value] = [
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::CONNECTED,
        ];
    }
}

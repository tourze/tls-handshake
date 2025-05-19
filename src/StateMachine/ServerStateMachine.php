<?php

namespace Tourze\TLSHandshake\StateMachine;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * 服务器握手状态机实现
 */
class ServerStateMachine extends AbstractHandshakeStateMachine
{
    /**
     * {@inheritdoc}
     */
    protected function initializeStateTransitions(): void
    {
        // 初始状态下，接收到ClientHello后发送ServerHello
        $this->stateTransitions[HandshakeStateEnum::INITIAL->value] = [
            HandshakeMessageType::CLIENT_HELLO->value => HandshakeStateEnum::WAIT_CERTIFICATE,
        ];
        
        // 发送证书后，发送ServerKeyExchange（如果需要）
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE->value] = [
            HandshakeMessageType::CERTIFICATE->value => HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE,
        ];

        // 发送ServerKeyExchange后，发送ServerHelloDone
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE->value] = [
            HandshakeMessageType::SERVER_KEY_EXCHANGE->value => HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
        ];

        // 发送ServerHelloDone后，等待客户端的KeyExchange
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO_DONE->value] = [
            HandshakeMessageType::SERVER_HELLO_DONE->value => HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
        ];
        
        // 收到ClientKeyExchange后，如果需要则等待CertificateVerify，否则等待ChangeCipherSpec和Finished
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE->value] = [
            HandshakeMessageType::CLIENT_KEY_EXCHANGE->value => HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
            // 如果不需要客户端证书验证，直接等待ChangeCipherSpec和Finished
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::WAIT_FINISHED,
        ];
        
        // 收到CertificateVerify后，等待ChangeCipherSpec和Finished
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY->value] = [
            HandshakeMessageType::CERTIFICATE_VERIFY->value => HandshakeStateEnum::WAIT_FINISHED,
        ];

        // 收到客户端Finished后，发送服务器Finished，握手完成
        $this->stateTransitions[HandshakeStateEnum::WAIT_FINISHED->value] = [
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::CONNECTED,
        ];
    }
}

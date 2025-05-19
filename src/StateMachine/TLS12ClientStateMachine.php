<?php

namespace Tourze\TLSHandshake\StateMachine;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS 1.2客户端握手状态机实现
 */
class TLS12ClientStateMachine extends AbstractHandshakeStateMachine
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
        
        // 收到ServerHelloDone后，发送ClientKeyExchange
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO_DONE->value] = [
            HandshakeMessageType::SERVER_HELLO_DONE->value => HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
        ];
        
        // 发送ClientKeyExchange后，发送ChangeCipherSpec
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE->value] = [
            HandshakeMessageType::CLIENT_KEY_EXCHANGE->value => HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
        ];
        
        // ChangeCipherSpec后，发送Finished
        $this->stateTransitions[HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC->value] = [
            // ChangeCipherSpec不是握手消息，状态转换需要手动处理
        ];
        
        // 收到服务器Finished消息后，握手完成
        $this->stateTransitions[HandshakeStateEnum::WAIT_FINISHED->value] = [
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::CONNECTED,
        ];
        
        // 可选：如果客户端需要提供证书
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE->value][HandshakeMessageType::CERTIFICATE_REQUEST->value] = HandshakeStateEnum::WAIT_SERVER_HELLO_DONE;
        
        // 当收到证书请求并发送了客户端证书后，需要发送CertificateVerify
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY->value] = [
            HandshakeMessageType::CERTIFICATE_VERIFY->value => HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
        ];
    }
    
    /**
     * 检查是否可以安全跳过当前状态
     * 
     * @param HandshakeStateEnum $currentState 当前状态
     * @return HandshakeStateEnum|null 可跳转的状态或null
     */
    public function canSkipState(HandshakeStateEnum $currentState): ?HandshakeStateEnum
    {
        // 某些状态可能是可选的，可以安全地跳过
        return match($currentState) {
            // 如果服务器未发送ServerKeyExchange，可直接进入等待ServerHelloDone状态
            HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE => HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
            // 如果未要求客户端证书，可跳过证书验证
            HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY => HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
            default => null,
        };
    }
    
    /**
     * 处理ChangeCipherSpec消息（非握手消息），转换到Finished状态
     * 
     * @return void
     */
    public function processChangeCipherSpec(): void
    {
        if ($this->currentState === HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC) {
            $this->transitionTo(HandshakeStateEnum::WAIT_FINISHED);
        } else {
            $this->transitionTo(HandshakeStateEnum::ERROR);
        }
    }
} 
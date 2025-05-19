<?php

namespace Tourze\TLSHandshake\StateMachine;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS 1.2服务器握手状态机实现
 */
class TLS12ServerStateMachine extends AbstractHandshakeStateMachine
{
    /**
     * 是否需要客户端证书
     *
     * @var bool
     */
    private bool $clientCertificateRequired = false;

    /**
     * {@inheritdoc}
     */
    protected function initializeStateTransitions(): void
    {
        // 初始状态下，接收到ClientHello后发送ServerHello
        $this->stateTransitions[HandshakeStateEnum::INITIAL->value] = [
            HandshakeMessageType::CLIENT_HELLO->value => HandshakeStateEnum::WAIT_SERVER_HELLO,
        ];
        
        // 发送ServerHello后，发送Certificate
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO->value] = [
            HandshakeMessageType::SERVER_HELLO->value => HandshakeStateEnum::WAIT_CERTIFICATE,
        ];
        
        // 发送证书后，发送ServerKeyExchange（如果需要）
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE->value] = [
            HandshakeMessageType::CERTIFICATE->value => HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE,
        ];

        // 发送ServerKeyExchange后，发送证书请求(可选)或直接发送ServerHelloDone
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE->value] = [
            HandshakeMessageType::SERVER_KEY_EXCHANGE->value => HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
            // 如果需要客户端证书，发送证书请求
            HandshakeMessageType::CERTIFICATE_REQUEST->value => HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
        ];

        // 发送ServerHelloDone后，等待客户端的响应
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO_DONE->value] = [
            HandshakeMessageType::SERVER_HELLO_DONE->value => HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
        ];
        
        // 如果要求客户端证书，等待客户端证书
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE->value] = [
            // 如果客户端发送证书
            HandshakeMessageType::CERTIFICATE->value => HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT,
            // 如果客户端不需要发送证书或发送空证书
            HandshakeMessageType::CLIENT_KEY_EXCHANGE->value => HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
        ];
        
        // 接收到客户端证书后，等待客户端密钥交换
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT->value] = [
            HandshakeMessageType::CLIENT_KEY_EXCHANGE->value => HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
        ];
        
        // 接收到客户端密钥交换后，等待证书验证
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY->value] = [
            HandshakeMessageType::CERTIFICATE_VERIFY->value => HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
        ];

        // ChangeCipherSpec不是握手消息，状态转换需要手动处理
        $this->stateTransitions[HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC->value] = [];
        
        // 等待客户端发送Finished消息
        $this->stateTransitions[HandshakeStateEnum::WAIT_FINISHED->value] = [
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::WAIT_CLIENT_FINISHED,
        ];
        
        // 接收到客户端的Finished后，服务器发送自己的Finished
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_FINISHED->value] = [];
    }
    
    /**
     * 设置是否需要客户端证书
     * 
     * @param bool $required 是否需要客户端证书
     * @return void
     */
    public function setClientCertificateRequired(bool $required): void
    {
        $this->clientCertificateRequired = $required;
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
    
    /**
     * 准备服务器的Finished消息，完成握手
     * 
     * @return void
     */
    public function prepareServerFinished(): void
    {
        if ($this->currentState === HandshakeStateEnum::WAIT_CLIENT_FINISHED) {
            // 服务器发送ChangeCipherSpec和Finished消息后，握手完成
            $this->transitionTo(HandshakeStateEnum::CONNECTED);
        } else {
            $this->transitionTo(HandshakeStateEnum::ERROR);
        }
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
            // 如果不需要ServerKeyExchange，可直接发送ServerHelloDone
            HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE => HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
            // 如果客户端没有提供证书或空证书，可跳过证书验证
            HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY => HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
            default => null,
        };
    }
} 
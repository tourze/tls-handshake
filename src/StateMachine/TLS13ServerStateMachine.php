<?php

namespace Tourze\TLSHandshake\StateMachine;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS 1.3服务器握手状态机实现
 */
class TLS13ServerStateMachine extends AbstractHandshakeStateMachine
{
    /**
     * 是否使用PSK模式
     *
     * @var bool
     */
    private bool $pskMode = false;
    
    /**
     * 是否支持0-RTT
     *
     * @var bool
     */
    private bool $earlyDataEnabled = false;
    
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
        // 初始状态下，接收到ClientHello
        $this->stateTransitions[HandshakeStateEnum::INITIAL->value] = [
            HandshakeMessageType::CLIENT_HELLO->value => HandshakeStateEnum::WAIT_SERVER_HELLO,
        ];
        
        // 发送ServerHello
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO->value] = [
            HandshakeMessageType::SERVER_HELLO->value => HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
        ];
        
        // 发送加密扩展，根据握手模式决定下一步
        $this->stateTransitions[HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS->value] = [
            HandshakeMessageType::ENCRYPTED_EXTENSIONS->value => HandshakeStateEnum::WAIT_CERTIFICATE,
        ];
        
        // 发送证书
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE->value] = [
            HandshakeMessageType::CERTIFICATE->value => HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
            // 可能同时发送证书请求
            HandshakeMessageType::CERTIFICATE_REQUEST->value => HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
        ];
        
        // 发送证书验证
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY->value] = [
            HandshakeMessageType::CERTIFICATE_VERIFY->value => HandshakeStateEnum::WAIT_FINISHED,
        ];
        
        // 发送Finished消息
        $this->stateTransitions[HandshakeStateEnum::WAIT_FINISHED->value] = [
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::WAIT_CLIENT_FINISHED,
        ];
        
        // 等待客户端Finished消息
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_FINISHED->value] = [
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::WAIT_NEW_SESSION_TICKET,
        ];
        
        // 发送NewSessionTicket完成握手
        $this->stateTransitions[HandshakeStateEnum::WAIT_NEW_SESSION_TICKET->value] = [
            HandshakeMessageType::NEW_SESSION_TICKET->value => HandshakeStateEnum::CONNECTED,
        ];
        
        // 处理0-RTT早期数据
        $this->stateTransitions[HandshakeStateEnum::PROCESS_EARLY_DATA->value] = [
            // 0-RTT处理完成后继续正常握手
        ];
        
        // 等待客户端证书
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE->value] = [
            HandshakeMessageType::CERTIFICATE->value => HandshakeStateEnum::WAIT_CLIENT_VERIFY,
        ];
        
        // 等待客户端证书验证
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_VERIFY->value] = [
            HandshakeMessageType::CERTIFICATE_VERIFY->value => HandshakeStateEnum::WAIT_CLIENT_FINISHED,
        ];
    }
    
    /**
     * 设置是否使用PSK模式
     * 
     * @param bool $enabled 是否启用PSK模式
     * @return void
     */
    public function setPSKMode(bool $enabled): void
    {
        $this->pskMode = $enabled;
        
        // 在PSK模式下，更新状态转换逻辑
        if ($enabled) {
            $this->stateTransitions[HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS->value][HandshakeMessageType::ENCRYPTED_EXTENSIONS->value] = HandshakeStateEnum::WAIT_FINISHED;
        } else {
            $this->stateTransitions[HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS->value][HandshakeMessageType::ENCRYPTED_EXTENSIONS->value] = HandshakeStateEnum::WAIT_CERTIFICATE;
        }
    }
    
    /**
     * 设置是否启用0-RTT早期数据
     * 
     * @param bool $enabled 是否启用0-RTT
     * @return void
     */
    public function setEarlyDataEnabled(bool $enabled): void
    {
        $this->earlyDataEnabled = $enabled;
        
        // 更新初始状态的转换
        if ($enabled) {
            $this->stateTransitions[HandshakeStateEnum::INITIAL->value][HandshakeMessageType::CLIENT_HELLO->value] = HandshakeStateEnum::PROCESS_EARLY_DATA;
        } else {
            $this->stateTransitions[HandshakeStateEnum::INITIAL->value][HandshakeMessageType::CLIENT_HELLO->value] = HandshakeStateEnum::WAIT_SERVER_HELLO;
        }
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
     * 处理完早期数据后继续握手流程
     * 
     * @return void
     */
    public function earlyDataProcessed(): void
    {
        if ($this->currentState === HandshakeStateEnum::PROCESS_EARLY_DATA) {
            $this->transitionTo(HandshakeStateEnum::WAIT_SERVER_HELLO);
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
        // PSK模式下可以跳过的状态
        if ($this->pskMode) {
            return match($currentState) {
                // PSK模式下可以跳过证书状态
                HandshakeStateEnum::WAIT_CERTIFICATE => HandshakeStateEnum::WAIT_FINISHED,
                HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY => HandshakeStateEnum::WAIT_FINISHED,
                default => null,
            };
        }
        
        return null;
    }
    
    /**
     * 判断是否需要请求客户端证书
     * 
     * @return bool
     */
    public function shouldRequestClientCertificate(): bool
    {
        return $this->clientCertificateRequired &&
               $this->currentState === HandshakeStateEnum::WAIT_CERTIFICATE;
    }
} 
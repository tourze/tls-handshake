<?php

namespace Tourze\TLSHandshake\StateMachine;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS 1.3客户端握手状态机实现
 */
class TLS13ClientStateMachine extends AbstractHandshakeStateMachine
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
     * {@inheritdoc}
     */
    protected function initializeStateTransitions(): void
    {
        // 初始状态下，发送ClientHello后等待ServerHello
        $this->stateTransitions[HandshakeStateEnum::INITIAL->value] = [
            HandshakeMessageType::CLIENT_HELLO->value => HandshakeStateEnum::WAIT_SERVER_HELLO,
        ];
        
        // 收到ServerHello后，等待加密扩展
        $this->stateTransitions[HandshakeStateEnum::WAIT_SERVER_HELLO->value] = [
            HandshakeMessageType::SERVER_HELLO->value => HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
        ];
        
        // 收到加密扩展后，等待证书(如果需要)或直接等待Finished
        $this->stateTransitions[HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS->value] = [
            HandshakeMessageType::ENCRYPTED_EXTENSIONS->value => HandshakeStateEnum::WAIT_CERTIFICATE,
            // PSK模式可能没有证书，直接等待Finished
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::WAIT_NEW_SESSION_TICKET,
        ];
        
        // 收到证书后，等待证书验证
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE->value] = [
            HandshakeMessageType::CERTIFICATE->value => HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
            // 如果服务器不提供证书
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::WAIT_NEW_SESSION_TICKET,
        ];
        
        // 收到证书验证后，等待Finished
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY->value] = [
            HandshakeMessageType::CERTIFICATE_VERIFY->value => HandshakeStateEnum::WAIT_FINISHED,
        ];
        
        // 收到Finished后，握手基本完成，等待NewSessionTicket
        $this->stateTransitions[HandshakeStateEnum::WAIT_FINISHED->value] = [
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::WAIT_NEW_SESSION_TICKET,
        ];
        
        // 收到NewSessionTicket后，完全握手完成
        $this->stateTransitions[HandshakeStateEnum::WAIT_NEW_SESSION_TICKET->value] = [
            HandshakeMessageType::NEW_SESSION_TICKET->value => HandshakeStateEnum::CONNECTED,
            // 也可能直接完成，不接收NewSessionTicket
            HandshakeMessageType::FINISHED->value => HandshakeStateEnum::CONNECTED,
        ];
        
        // 如果握手过程中需要客户端证书
        $this->stateTransitions[HandshakeStateEnum::WAIT_CERTIFICATE->value][HandshakeMessageType::CERTIFICATE_REQUEST->value] = HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE;
        
        // 客户端发送证书后等待服务器的Finished
        $this->stateTransitions[HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE->value] = [
            HandshakeMessageType::CERTIFICATE->value => HandshakeStateEnum::WAIT_FINISHED,
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
        
        // 在PSK模式下，更新部分状态转换
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
     * 处理服务器拒绝PSK/0-RTT情况
     * 
     * @return void
     */
    public function handlePSKRejection(): void
    {
        // 如果服务器拒绝了PSK，需要进行完整握手
        if ($this->currentState === HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS) {
            $this->pskMode = false;
        }
    }
} 
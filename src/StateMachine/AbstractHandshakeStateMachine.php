<?php

namespace Tourze\TLSHandshake\StateMachine;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * 握手状态机抽象基类
 */
abstract class AbstractHandshakeStateMachine implements HandshakeStateMachineInterface
{
    /**
     * 当前状态
     *
     * @var HandshakeStateEnum
     */
    protected HandshakeStateEnum $currentState = HandshakeStateEnum::INITIAL;
    
    /**
     * 有效状态列表
     *
     * @var array<HandshakeStateEnum>
     */
    protected array $validStates = [];
    
    /**
     * 状态转换映射
     * [当前状态->value][消息类型->value] => 新状态
     *
     * @var array<string, array<int, HandshakeStateEnum>>
     */
    protected array $stateTransitions = [];
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->initializeValidStates();
        $this->initializeStateTransitions();
    }
    
    /**
     * 初始化有效状态列表
     */
    protected function initializeValidStates(): void
    {
        $this->validStates = [
            HandshakeStateEnum::INITIAL,
            HandshakeStateEnum::WAIT_SERVER_HELLO,
            HandshakeStateEnum::WAIT_CERTIFICATE,
            HandshakeStateEnum::WAIT_SERVER_KEY_EXCHANGE,
            HandshakeStateEnum::WAIT_SERVER_HELLO_DONE,
            HandshakeStateEnum::WAIT_CLIENT_CERTIFICATE,
            HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE,
            HandshakeStateEnum::WAIT_CLIENT_KEY_EXCHANGE_WITH_CERT,
            HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
            HandshakeStateEnum::WAIT_CHANGE_CIPHER_SPEC,
            HandshakeStateEnum::WAIT_FINISHED,
            HandshakeStateEnum::WAIT_CLIENT_FINISHED,
            HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
            HandshakeStateEnum::WAIT_NEW_SESSION_TICKET,
            HandshakeStateEnum::PROCESS_EARLY_DATA,
            HandshakeStateEnum::WAIT_CLIENT_VERIFY,
            HandshakeStateEnum::CONNECTED,
            HandshakeStateEnum::ERROR,
        ];
    }
    
    /**
     * 初始化状态转换映射
     */
    abstract protected function initializeStateTransitions(): void;
    
    /**
     * {@inheritdoc}
     */
    public function getCurrentState(): HandshakeStateEnum
    {
        return $this->currentState;
    }
    
    /**
     * {@inheritdoc}
     */
    public function transitionTo(HandshakeStateEnum $state): void
    {
        if (!in_array($state, $this->validStates, true)) {
            throw new \InvalidArgumentException("无效的状态: {$state->value}");
        }
        
        $this->currentState = $state;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getNextState(HandshakeMessageType $messageType): HandshakeStateEnum
    {
        if (isset($this->stateTransitions[$this->currentState->value][$messageType->value])) {
            return $this->stateTransitions[$this->currentState->value][$messageType->value];
        }
        
        // 未定义的转换导致错误状态
        return HandshakeStateEnum::ERROR;
    }
    
    /**
     * {@inheritdoc}
     */
    public function isInErrorState(): bool
    {
        return $this->currentState === HandshakeStateEnum::ERROR;
    }
    
    /**
     * {@inheritdoc}
     */
    public function isHandshakeCompleted(): bool
    {
        return $this->currentState === HandshakeStateEnum::CONNECTED;
    }
    
    /**
     * {@inheritdoc}
     */
    public function reset(): void
    {
        $this->currentState = HandshakeStateEnum::INITIAL;
    }
}

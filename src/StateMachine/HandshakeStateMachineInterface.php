<?php

namespace Tourze\TLSHandshake\StateMachine;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * 握手状态机接口
 */
interface HandshakeStateMachineInterface
{
    /**
     * 获取当前状态
     *
     * @return HandshakeStateEnum 当前状态
     */
    public function getCurrentState(): HandshakeStateEnum;
    
    /**
     * 转换到新状态
     *
     * @param HandshakeStateEnum $state 目标状态
     * @return void
     * @throws \InvalidArgumentException 当状态无效时
     */
    public function transitionTo(HandshakeStateEnum $state): void;
    
    /**
     * 基于消息类型确定下一个状态
     *
     * @param HandshakeMessageType $messageType 握手消息类型
     * @return HandshakeStateEnum 下一个状态
     */
    public function getNextState(HandshakeMessageType $messageType): HandshakeStateEnum;
    
    /**
     * 检查是否处于错误状态
     *
     * @return bool
     */
    public function isInErrorState(): bool;
    
    /**
     * 检查握手是否完成
     *
     * @return bool
     */
    public function isHandshakeCompleted(): bool;
    
    /**
     * 重置状态机到初始状态
     *
     * @return void
     */
    public function reset(): void;
}

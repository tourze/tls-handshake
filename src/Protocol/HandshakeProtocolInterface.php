<?php

namespace Tourze\TLSHandshake\Protocol;

/**
 * TLS握手协议接口
 */
interface HandshakeProtocolInterface
{
    /**
     * 开始握手流程
     *
     * @return void
     */
    public function startHandshake(): void;
    
    /**
     * 处理收到的握手消息
     *
     * @param string $message 握手消息数据
     * @return string|null 返回响应消息，如果没有则返回null
     */
    public function processHandshakeMessage(string $message): ?string;
    
    /**
     * 获取当前握手状态
     *
     * @return HandshakeProtocolState 当前状态
     */
    public function getState(): HandshakeProtocolState;
    
    /**
     * 握手是否已完成
     *
     * @return bool
     */
    public function isHandshakeCompleted(): bool;
    
    /**
     * 标记握手过程已完成
     *
     * @return void
     */
    public function completeHandshake(): void;
    
    /**
     * 获取协议版本
     *
     * @return string|null
     */
    public function getVersion(): ?string;
    
    /**
     * 设置协议版本
     *
     * @param string $version 协议版本
     * @return void
     */
    public function setVersion(string $version): void;
}

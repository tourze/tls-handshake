<?php

namespace Tourze\TLSHandshake\Protocol;

/**
 * 握手协议抽象基类
 */
abstract class AbstractHandshakeProtocol implements HandshakeProtocolInterface
{
    /**
     * 当前握手状态
     *
     * @var HandshakeProtocolState
     */
    protected HandshakeProtocolState $state = HandshakeProtocolState::NOT_STARTED;
    
    /**
     * TLS协议版本
     *
     * @var string|null
     */
    protected ?string $version = null;
    
    /**
     * {@inheritdoc}
     */
    public function startHandshake(): void
    {
        $this->state = HandshakeProtocolState::IN_PROGRESS;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getState(): HandshakeProtocolState
    {
        return $this->state;
    }
    
    /**
     * {@inheritdoc}
     */
    public function isHandshakeCompleted(): bool
    {
        return $this->state === HandshakeProtocolState::COMPLETED;
    }
    
    /**
     * {@inheritdoc}
     */
    public function completeHandshake(): void
    {
        $this->state = HandshakeProtocolState::COMPLETED;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getVersion(): ?string
    {
        return $this->version;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setVersion(string $version): void
    {
        $this->version = $version;
    }
}

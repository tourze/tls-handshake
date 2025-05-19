<?php

namespace Tourze\TLSHandshake\Handshake;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * 握手流程抽象实现
 */
abstract class AbstractHandshakeFlow implements HandshakeFlowInterface
{
    /**
     * 当前握手阶段
     *
     * @var HandshakeStage
     */
    protected HandshakeStage $currentStage = HandshakeStage::INITIAL;
    
    /**
     * {@inheritdoc}
     */
    public function getCurrentStage(): HandshakeStage
    {
        return $this->currentStage;
    }
    
    /**
     * {@inheritdoc}
     */
    public function advanceToStage(HandshakeStage $stage): void
    {
        if ($stage->value < $this->currentStage->value) {
            throw new \InvalidArgumentException("不能回退到先前的握手阶段");
        }
        
        $this->currentStage = $stage;
    }
    
    /**
     * {@inheritdoc}
     */
    public function isStageCompleted(HandshakeStage $stage): bool
    {
        return $this->currentStage->value > $stage->value;
    }
    
    /**
     * {@inheritdoc}
     */
    public function acceptsMessageType(HandshakeMessageType $messageType): bool
    {
        $expectedTypes = $this->getExpectedMessageTypes($this->currentStage);
        return in_array($messageType, $expectedTypes, true);
    }
}

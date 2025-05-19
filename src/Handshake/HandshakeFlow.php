<?php

namespace Tourze\TLSHandshake\Handshake;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * 基本握手流程实现
 * 
 * 为TLS 1.2和TLS 1.3提供通用的握手流程框架
 */
class HandshakeFlow extends AbstractHandshakeFlow
{
    /**
     * 阶段到消息类型的映射
     *
     * @var array<HandshakeStage, array<HandshakeMessageType>>
     */
    protected array $stageMessageMap = [];
    
    /**
     * 构造函数，初始化阶段消息映射
     */
    public function __construct()
    {
        $this->initializeStageMessageMap();
    }
    
    /**
     * 初始化阶段消息映射
     */
    protected function initializeStageMessageMap(): void
    {
        // 初始阶段 - 客户端发送 ClientHello，服务端可能发送 HelloRequest
        $this->stageMessageMap[HandshakeStage::INITIAL->value] = [
            HandshakeMessageType::CLIENT_HELLO,
            HandshakeMessageType::HELLO_REQUEST,
        ];
        
        // 协商阶段 - 服务器发送 ServerHello
        $this->stageMessageMap[HandshakeStage::NEGOTIATING->value] = [
            HandshakeMessageType::SERVER_HELLO,
            HandshakeMessageType::ENCRYPTED_EXTENSIONS, // TLS 1.3
        ];
        
        // 密钥交换阶段
        $this->stageMessageMap[HandshakeStage::KEY_EXCHANGE->value] = [
            HandshakeMessageType::SERVER_KEY_EXCHANGE,
            HandshakeMessageType::CLIENT_KEY_EXCHANGE,
        ];
        
        // 认证阶段
        $this->stageMessageMap[HandshakeStage::AUTHENTICATION->value] = [
            HandshakeMessageType::CERTIFICATE,
            HandshakeMessageType::CERTIFICATE_REQUEST,
            HandshakeMessageType::CERTIFICATE_VERIFY,
            HandshakeMessageType::SERVER_HELLO_DONE,
        ];
        
        // 完成阶段
        $this->stageMessageMap[HandshakeStage::FINISHED->value] = [
            HandshakeMessageType::FINISHED,
            HandshakeMessageType::NEW_SESSION_TICKET,
        ];
    }
    
    /**
     * {@inheritdoc}
     */
    public function getExpectedMessageTypes(HandshakeStage $stage): array
    {
        return $this->stageMessageMap[$stage->value] ?? [];
    }
}

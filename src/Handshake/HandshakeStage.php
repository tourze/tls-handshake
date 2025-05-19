<?php

namespace Tourze\TLSHandshake\Handshake;

/**
 * 握手阶段枚举
 */
enum HandshakeStage: int
{
    /**
     * 握手阶段：初始阶段（交换 Hello 消息）
     */
    case INITIAL = 1;
    
    /**
     * 握手阶段：协商阶段（协商加密套件、协议版本等）
     */
    case NEGOTIATING = 2;
    
    /**
     * 握手阶段：密钥交换阶段
     */
    case KEY_EXCHANGE = 3;
    
    /**
     * 握手阶段：认证阶段
     */
    case AUTHENTICATION = 4;
    
    /**
     * 握手阶段：完成阶段
     */
    case FINISHED = 5;
}

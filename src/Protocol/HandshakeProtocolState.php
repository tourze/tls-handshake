<?php

namespace Tourze\TLSHandshake\Protocol;

/**
 * 握手协议状态枚举
 */
enum HandshakeProtocolState: int
{
    /**
     * 握手状态：未开始
     */
    case NOT_STARTED = 0;
    
    /**
     * 握手状态：进行中
     */
    case IN_PROGRESS = 1;
    
    /**
     * 握手状态：已完成
     */
    case COMPLETED = 2;
    
    /**
     * 握手状态：失败
     */
    case FAILED = 3;
}

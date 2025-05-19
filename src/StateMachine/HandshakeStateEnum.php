<?php

namespace Tourze\TLSHandshake\StateMachine;

/**
 * TLS握手状态枚举
 */
enum HandshakeStateEnum: string
{
    /**
     * 初始状态
     */
    case INITIAL = 'INITIAL';
    
    /**
     * 等待服务器Hello消息
     */
    case WAIT_SERVER_HELLO = 'WAIT_SERVER_HELLO';
    
    /**
     * 等待证书消息
     */
    case WAIT_CERTIFICATE = 'WAIT_CERTIFICATE';
    
    /**
     * 等待服务器密钥交换消息
     */
    case WAIT_SERVER_KEY_EXCHANGE = 'WAIT_SERVER_KEY_EXCHANGE';
    
    /**
     * 等待服务器Hello完成消息
     */
    case WAIT_SERVER_HELLO_DONE = 'WAIT_SERVER_HELLO_DONE';
    
    /**
     * 等待客户端证书
     */
    case WAIT_CLIENT_CERTIFICATE = 'WAIT_CLIENT_CERTIFICATE';
    
    /**
     * 等待客户端密钥交换
     */
    case WAIT_CLIENT_KEY_EXCHANGE = 'WAIT_CLIENT_KEY_EXCHANGE';
    
    /**
     * 等待证书验证
     */
    case WAIT_CERTIFICATE_VERIFY = 'WAIT_CERTIFICATE_VERIFY';
    
    /**
     * 等待修改加密规范
     */
    case WAIT_CHANGE_CIPHER_SPEC = 'WAIT_CHANGE_CIPHER_SPEC';
    
    /**
     * 等待握手完成消息
     */
    case WAIT_FINISHED = 'WAIT_FINISHED';
    
    /**
     * TLS连接已建立
     */
    case CONNECTED = 'CONNECTED';
    
    /**
     * 握手错误状态
     */
    case ERROR = 'ERROR';
    
    /**
     * TLS 1.3特有：等待加密扩展
     */
    case WAIT_ENCRYPTED_EXTENSIONS = 'WAIT_ENCRYPTED_EXTENSIONS';
    
    /**
     * TLS 1.3特有：等待新的会话凭证
     */
    case WAIT_NEW_SESSION_TICKET = 'WAIT_NEW_SESSION_TICKET';
}

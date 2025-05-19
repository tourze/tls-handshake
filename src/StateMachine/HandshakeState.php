<?php

namespace Tourze\TLSHandshake\StateMachine;

/**
 * TLS握手状态常量定义
 */
final class HandshakeState
{
    /**
     * 初始状态
     */
    public const INITIAL = 'INITIAL';
    
    /**
     * 等待服务器Hello消息
     */
    public const WAIT_SERVER_HELLO = 'WAIT_SERVER_HELLO';
    
    /**
     * 等待证书消息
     */
    public const WAIT_CERTIFICATE = 'WAIT_CERTIFICATE';
    
    /**
     * 等待服务器密钥交换消息
     */
    public const WAIT_SERVER_KEY_EXCHANGE = 'WAIT_SERVER_KEY_EXCHANGE';
    
    /**
     * 等待服务器Hello完成消息
     */
    public const WAIT_SERVER_HELLO_DONE = 'WAIT_SERVER_HELLO_DONE';
    
    /**
     * 等待客户端证书
     */
    public const WAIT_CLIENT_CERTIFICATE = 'WAIT_CLIENT_CERTIFICATE';
    
    /**
     * 等待客户端密钥交换
     */
    public const WAIT_CLIENT_KEY_EXCHANGE = 'WAIT_CLIENT_KEY_EXCHANGE';
    
    /**
     * 等待证书验证
     */
    public const WAIT_CERTIFICATE_VERIFY = 'WAIT_CERTIFICATE_VERIFY';
    
    /**
     * 等待修改加密规范
     */
    public const WAIT_CHANGE_CIPHER_SPEC = 'WAIT_CHANGE_CIPHER_SPEC';
    
    /**
     * 等待握手完成消息
     */
    public const WAIT_FINISHED = 'WAIT_FINISHED';
    
    /**
     * TLS连接已建立
     */
    public const CONNECTED = 'CONNECTED';
    
    /**
     * 握手错误状态
     */
    public const ERROR = 'ERROR';
    
    /**
     * TLS 1.3特有：等待加密扩展
     */
    public const WAIT_ENCRYPTED_EXTENSIONS = 'WAIT_ENCRYPTED_EXTENSIONS';
    
    /**
     * TLS 1.3特有：等待新的会话凭证
     */
    public const WAIT_NEW_SESSION_TICKET = 'WAIT_NEW_SESSION_TICKET';
} 
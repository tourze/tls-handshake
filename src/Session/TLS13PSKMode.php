<?php

namespace Tourze\TLSHandshake\Session;

/**
 * TLS 1.3 PSK模式
 * 
 * 定义TLS 1.3中的PSK密钥交换模式
 */
class TLS13PSKMode
{
    /**
     * 仅PSK密钥交换模式
     * 
     * 使用预共享密钥而不额外进行DH密钥协商
     */
    public const PSK_KE = 0;
    
    /**
     * PSK与DHE密钥交换模式
     * 
     * 使用预共享密钥并额外进行DH密钥协商，提供前向安全性
     */
    public const PSK_DHE_KE = 1;
    
    /**
     * 检查PSK模式是否有效
     * 
     * @param int $mode PSK模式
     * @return bool 是否有效
     */
    public static function isValidMode(int $mode): bool
    {
        return $mode === self::PSK_KE || $mode === self::PSK_DHE_KE;
    }
    
    /**
     * 获取模式名称
     * 
     * @param int $mode PSK模式
     * @return string 模式名称
     */
    public static function getModeName(int $mode): string
    {
        return match($mode) {
            self::PSK_KE => 'psk_ke',
            self::PSK_DHE_KE => 'psk_dhe_ke',
            default => 'unknown'
        };
    }
    
    /**
     * 检查是否为仅PSK模式
     * 
     * 仅PSK模式不提供前向安全性
     * 
     * @param int $mode PSK模式
     * @return bool 是否为仅PSK模式
     */
    public static function isPSKOnlyMode(int $mode): bool
    {
        return $mode === self::PSK_KE;
    }
    
    /**
     * 获取所有支持的PSK模式
     * 
     * @return array<int> 模式列表
     */
    public static function getAllModes(): array
    {
        return [self::PSK_KE, self::PSK_DHE_KE];
    }
} 
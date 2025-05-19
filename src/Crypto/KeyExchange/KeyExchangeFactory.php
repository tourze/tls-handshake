<?php

namespace Tourze\TLSHandshake\Crypto\KeyExchange;

/**
 * 密钥交换工厂类
 * 
 * 用于创建适合不同加密套件的密钥交换实现
 */
class KeyExchangeFactory
{
    /**
     * 创建密钥交换实例
     * 
     * @param string $type 密钥交换类型（"RSA", "DHE", "ECDHE", "PSK", "TLS13"）
     * @return KeyExchangeInterface 密钥交换实例
     * @throws \InvalidArgumentException 如果类型不支持
     */
    public static function create(string $type): KeyExchangeInterface
    {
        return match (strtoupper($type)) {
            'RSA' => new RSAKeyExchange(),
            'DHE' => new DHEKeyExchange(),
            'ECDHE' => new ECDHEKeyExchange(),
            'PSK' => new PSKKeyExchange(),
            'TLS13' => new TLS13KeyExchange(),
            default => throw new \InvalidArgumentException("Unsupported key exchange type: $type"),
        };
    }
    
    /**
     * 根据加密套件创建密钥交换实例
     * 
     * @param string $cipherSuite 加密套件名称
     * @param int $tlsVersion TLS版本
     * @return KeyExchangeInterface 密钥交换实例
     * @throws \InvalidArgumentException 如果加密套件不支持
     */
    public static function createFromCipherSuite(string $cipherSuite, int $tlsVersion): KeyExchangeInterface
    {
        // TLS 1.3使用统一的密钥共享机制
        if ($tlsVersion >= 0x0304) { // TLS 1.3
            return new TLS13KeyExchange();
        }
        
        // 分析加密套件名称以确定密钥交换类型
        if (str_contains($cipherSuite, 'ECDHE_')) {
            return new ECDHEKeyExchange();
        } elseif (str_contains($cipherSuite, 'DHE_') || str_contains($cipherSuite, 'EDH_')) {
            return new DHEKeyExchange();
        } elseif (str_contains($cipherSuite, 'PSK_')) {
            return new PSKKeyExchange();
        } elseif (str_contains($cipherSuite, 'RSA_')) {
            return new RSAKeyExchange();
        } else {
            // 默认为RSA密钥交换
            return new RSAKeyExchange();
        }
    }
} 
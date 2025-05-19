<?php

namespace Tourze\TLSHandshake\Crypto;

/**
 * TLS加密套件
 * 
 * 参考RFC 5246 (TLS 1.2) 和 RFC 8446 (TLS 1.3)
 */
class CipherSuite
{
    // TLS 1.2加密套件常量
    // 格式: TLS_密钥交换算法_WITH_对称加密算法_消息认证码
    
    /**
     * TLS_RSA_WITH_NULL_MD5
     * (RFC 5246 - 仅用于测试，不建议在生产环境使用)
     */
    public const TLS_RSA_WITH_NULL_MD5 = 0x0001;
    
    /**
     * TLS_RSA_WITH_NULL_SHA
     * (RFC 5246 - 仅用于测试，不建议在生产环境使用)
     */
    public const TLS_RSA_WITH_NULL_SHA = 0x0002;
    
    /**
     * TLS_RSA_WITH_AES_128_CBC_SHA
     * (RFC 5246)
     */
    public const TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F;
    
    /**
     * TLS_RSA_WITH_AES_256_CBC_SHA
     * (RFC 5246)
     */
    public const TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035;
    
    /**
     * TLS_RSA_WITH_AES_128_CBC_SHA256
     * (RFC 5246)
     */
    public const TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C;
    
    /**
     * TLS_RSA_WITH_AES_256_CBC_SHA256
     * (RFC 5246)
     */
    public const TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D;
    
    /**
     * TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
     * (RFC 5289)
     */
    public const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023;
    
    /**
     * TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
     * (RFC 5289)
     */
    public const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024;
    
    /**
     * TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
     * (RFC 5289)
     */
    public const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027;
    
    /**
     * TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
     * (RFC 5289)
     */
    public const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028;
    
    /**
     * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
     * (RFC 5289)
     */
    public const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B;
    
    /**
     * TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
     * (RFC 5289)
     */
    public const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C;
    
    /**
     * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
     * (RFC 5289)
     */
    public const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F;
    
    /**
     * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
     * (RFC 5289)
     */
    public const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030;
    
    // TLS 1.3加密套件常量
    // 格式: TLS_AEAD算法_HASH算法
    
    /**
     * TLS_AES_128_GCM_SHA256
     * (RFC 8446)
     */
    public const TLS_AES_128_GCM_SHA256 = 0x1301;
    
    /**
     * TLS_AES_256_GCM_SHA384
     * (RFC 8446)
     */
    public const TLS_AES_256_GCM_SHA384 = 0x1302;
    
    /**
     * TLS_CHACHA20_POLY1305_SHA256
     * (RFC 8446)
     */
    public const TLS_CHACHA20_POLY1305_SHA256 = 0x1303;
    
    /**
     * 加密套件值
     * 
     * @var int
     */
    private int $value;
    
    /**
     * 构造函数
     * 
     * @param int $value 加密套件值
     */
    public function __construct(int $value)
    {
        $this->value = $value;
    }
    
    /**
     * 获取加密套件值
     * 
     * @return int 加密套件值
     */
    public function getValue(): int
    {
        return $this->value;
    }
    
    /**
     * 获取加密套件名称
     * 
     * @return string 加密套件名称
     */
    public function getName(): string
    {
        return self::getCipherSuiteName($this->value);
    }
    
    /**
     * 判断是否为TLS 1.3加密套件
     * 
     * @return bool 是否为TLS 1.3加密套件
     */
    public function isTLS13(): bool
    {
        return ($this->value >= 0x1301 && $this->value <= 0x1303);
    }
    
    /**
     * 获取加密套件名称
     * 
     * @param int $value 加密套件值
     * @return string 加密套件名称
     */
    public static function getCipherSuiteName(int $value): string
    {
        return match($value) {
            self::TLS_RSA_WITH_NULL_MD5 => 'TLS_RSA_WITH_NULL_MD5',
            self::TLS_RSA_WITH_NULL_SHA => 'TLS_RSA_WITH_NULL_SHA',
            self::TLS_RSA_WITH_AES_128_CBC_SHA => 'TLS_RSA_WITH_AES_128_CBC_SHA',
            self::TLS_RSA_WITH_AES_256_CBC_SHA => 'TLS_RSA_WITH_AES_256_CBC_SHA',
            self::TLS_RSA_WITH_AES_128_CBC_SHA256 => 'TLS_RSA_WITH_AES_128_CBC_SHA256',
            self::TLS_RSA_WITH_AES_256_CBC_SHA256 => 'TLS_RSA_WITH_AES_256_CBC_SHA256',
            self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
            self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
            self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
            self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
            self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            self::TLS_AES_128_GCM_SHA256 => 'TLS_AES_128_GCM_SHA256',
            self::TLS_AES_256_GCM_SHA384 => 'TLS_AES_256_GCM_SHA384',
            self::TLS_CHACHA20_POLY1305_SHA256 => 'TLS_CHACHA20_POLY1305_SHA256',
            default => sprintf('Unknown CipherSuite (0x%04X)', $value),
        };
    }
    
    /**
     * 获取推荐的TLS 1.2加密套件列表（按优先级排序）
     * 
     * @return array<int> 推荐的TLS 1.2加密套件列表
     */
    public static function getRecommendedTLS12CipherSuites(): array
    {
        return [
            // 优先使用ECDHE带GCM的加密套件
            self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            
            // 然后是ECDHE带CBC的加密套件
            self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            
            // 最后是RSA加密套件（不具备前向保密特性）
            self::TLS_RSA_WITH_AES_256_CBC_SHA256,
            self::TLS_RSA_WITH_AES_128_CBC_SHA256,
            self::TLS_RSA_WITH_AES_256_CBC_SHA,
            self::TLS_RSA_WITH_AES_128_CBC_SHA,
        ];
    }
    
    /**
     * 获取推荐的TLS 1.3加密套件列表（按优先级排序）
     * 
     * @return array<int> 推荐的TLS 1.3加密套件列表
     */
    public static function getRecommendedTLS13CipherSuites(): array
    {
        return [
            self::TLS_AES_256_GCM_SHA384,
            self::TLS_CHACHA20_POLY1305_SHA256,
            self::TLS_AES_128_GCM_SHA256,
        ];
    }
}
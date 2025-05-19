<?php

namespace Tourze\TLSHandshake\Protocol;

/**
 * TLS协议版本枚举
 */
enum TLSVersion: int
{
    /**
     * SSL 3.0
     * 历史版本，不推荐使用
     */
    case SSL_3_0 = 0x0300;
    
    /**
     * TLS 1.0
     * 对应SSL 3.1，不推荐使用
     */
    case TLS_1_0 = 0x0301;
    
    /**
     * TLS 1.1
     * 不推荐使用
     */
    case TLS_1_1 = 0x0302;
    
    /**
     * TLS 1.2
     * 广泛使用的版本
     */
    case TLS_1_2 = 0x0303;
    
    /**
     * TLS 1.3
     * 最新版本，具有更好的安全性和性能
     */
    case TLS_1_3 = 0x0304;
    
    /**
     * 获取版本的名称
     * 
     * @return string 版本名称
     */
    public function getName(): string
    {
        return match($this) {
            self::SSL_3_0 => 'SSL 3.0',
            self::TLS_1_0 => 'TLS 1.0',
            self::TLS_1_1 => 'TLS 1.1',
            self::TLS_1_2 => 'TLS 1.2',
            self::TLS_1_3 => 'TLS 1.3',
        };
    }
    
    /**
     * 判断版本是否安全
     * 
     * @return bool 是否安全
     */
    public function isSecure(): bool
    {
        return match($this) {
            self::SSL_3_0 => false, // POODLE攻击
            self::TLS_1_0 => false, // BEAST攻击
            self::TLS_1_1 => false, // 存在已知漏洞
            self::TLS_1_2, self::TLS_1_3 => true,
        };
    }
    
    /**
     * 获取版本的名称（静态方法）
     * 
     * @param int $version 版本值
     * @return string 版本名称
     */
    public static function getVersionName(int $version): string
    {
        $enum = self::tryFrom($version);
        if ($enum === null) {
            return sprintf('Unknown (0x%04X)', $version);
        }
        
        return $enum->getName();
    }
    
    /**
     * 获取推荐的版本列表（按优先级排序）
     * 
     * @return array<TLSVersion> 推荐的版本列表
     */
    public static function getRecommendedVersions(): array
    {
        return [
            self::TLS_1_3,
            self::TLS_1_2,
        ];
    }
}
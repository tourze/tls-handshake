<?php

namespace Tourze\TLSHandshake\Extension;

/**
 * TLS命名组枚举
 * 
 * 定义了RFC规范中的椭圆曲线组和有限域组
 * 参考：RFC 8446 (TLS 1.3) Section 4.2.7
 */
enum NamedGroup: int
{
    /**
     * 保留值 (0x0000)
     */
    case RESERVED = 0x0000;
    
    // ECDHE组 (椭圆曲线)
    
    /**
     * secp256r1 曲线
     */
    case SECP256R1 = 0x0017;
    
    /**
     * secp384r1 曲线
     */
    case SECP384R1 = 0x0018;
    
    /**
     * secp521r1 曲线
     */
    case SECP521R1 = 0x0019;
    
    /**
     * x25519 曲线
     */
    case X25519 = 0x001D;
    
    /**
     * x448 曲线
     */
    case X448 = 0x001E;
    
    // FFDHE组 (有限域)
    
    /**
     * ffdhe2048
     */
    case FFDHE2048 = 0x0100;
    
    /**
     * ffdhe3072
     */
    case FFDHE3072 = 0x0101;
    
    /**
     * ffdhe4096
     */
    case FFDHE4096 = 0x0102;
    
    /**
     * ffdhe6144
     */
    case FFDHE6144 = 0x0103;
    
    /**
     * ffdhe8192
     */
    case FFDHE8192 = 0x0104;
    
    /**
     * 获取组名称
     * 
     * @return string 组名称
     */
    public function getName(): string
    {
        return match($this) {
            self::RESERVED => 'reserved',
            self::SECP256R1 => 'secp256r1',
            self::SECP384R1 => 'secp384r1',
            self::SECP521R1 => 'secp521r1',
            self::X25519 => 'x25519',
            self::X448 => 'x448',
            self::FFDHE2048 => 'ffdhe2048',
            self::FFDHE3072 => 'ffdhe3072',
            self::FFDHE4096 => 'ffdhe4096',
            self::FFDHE6144 => 'ffdhe6144',
            self::FFDHE8192 => 'ffdhe8192',
        };
    }
    
    /**
     * 检查该组是否是椭圆曲线组
     * 
     * @return bool 是否是椭圆曲线组
     */
    public function isEllipticCurve(): bool
    {
        return match($this) {
            self::SECP256R1, self::SECP384R1, self::SECP521R1, 
            self::X25519, self::X448 => true,
            default => false,
        };
    }
    
    /**
     * 检查该组是否是有限域组
     * 
     * @return bool 是否是有限域组
     */
    public function isFiniteField(): bool
    {
        return match($this) {
            self::FFDHE2048, self::FFDHE3072, self::FFDHE4096, 
            self::FFDHE6144, self::FFDHE8192 => true,
            default => false,
        };
    }
    
    /**
     * 获取推荐的TLS 1.3默认组
     * 
     * @return array<self> 推荐的默认组列表
     */
    public static function getRecommendedGroups(): array
    {
        return [
            self::X25519,     // 推荐作为第一选择
            self::SECP256R1,  // 广泛支持的备选
            self::SECP384R1,  // 更安全但较慢
            self::SECP521R1,  // 最安全但最慢
            self::FFDHE2048,  // 有限域兼容性选项
            self::FFDHE3072,  // 更安全的有限域选项
        ];
    }
}

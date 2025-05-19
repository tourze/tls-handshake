<?php

namespace Tourze\TLSHandshake\Extension;

/**
 * TLS扩展类型枚举
 * 
 * 定义了RFC规范中的TLS扩展类型常量
 */
enum ExtensionType: int
{
    /**
     * 服务器名称指示扩展
     */
    case SERVER_NAME = 0x0000;
    
    /**
     * 最大分片长度扩展
     */
    case MAX_FRAGMENT_LENGTH = 0x0001;
    
    /**
     * 客户端证书URL扩展
     */
    case CLIENT_CERTIFICATE_URL = 0x0002;
    
    /**
     * 受信任的CA密钥扩展
     */
    case TRUSTED_CA_KEYS = 0x0003;
    
    /**
     * 截断HMAC扩展
     */
    case TRUNCATED_HMAC = 0x0004;
    
    /**
     * 状态请求扩展
     */
    case STATUS_REQUEST = 0x0005;
    
    /**
     * 支持的组扩展（椭圆曲线组等）
     * 在TLS 1.2中称为"elliptic_curves"
     */
    case SUPPORTED_GROUPS = 0x000A;
    
    /**
     * 椭圆曲线点格式扩展
     */
    case EC_POINT_FORMATS = 0x000B;
    
    /**
     * 签名算法扩展
     */
    case SIGNATURE_ALGORITHMS = 0x000D;
    
    /**
     * 使用SRTP扩展
     */
    case USE_SRTP = 0x000E;
    
    /**
     * 心跳扩展
     */
    case HEARTBEAT = 0x000F;
    
    /**
     * 应用层协议协商扩展
     */
    case ALPN = 0x0010;
    
    /**
     * 签名证书时间戳扩展
     */
    case SIGNED_CERTIFICATE_TIMESTAMP = 0x0012;
    
    /**
     * 客户端证书类型扩展
     */
    case CLIENT_CERTIFICATE_TYPE = 0x0013;
    
    /**
     * 服务器证书类型扩展
     */
    case SERVER_CERTIFICATE_TYPE = 0x0014;
    
    /**
     * 填充扩展
     */
    case PADDING = 0x0015;
    
    /**
     * 先加密后MAC扩展
     */
    case ENCRYPT_THEN_MAC = 0x0016;
    
    /**
     * 扩展主密钥扩展
     */
    case EXTENDED_MASTER_SECRET = 0x0017;
    
    /**
     * 会话票据扩展
     */
    case SESSION_TICKET = 0x0023;
    
    /**
     * 预共享密钥扩展 (TLS 1.3)
     */
    case PRE_SHARED_KEY = 0x0029;
    
    /**
     * 早期数据指示扩展 (TLS 1.3)
     */
    case EARLY_DATA = 0x002A;
    
    /**
     * 支持的版本扩展 (TLS 1.3)
     */
    case SUPPORTED_VERSIONS = 0x002B;
    
    /**
     * Cookie扩展 (TLS 1.3)
     */
    case COOKIE = 0x002C;
    
    /**
     * PSK密钥交换模式扩展 (TLS 1.3)
     */
    case PSK_KEY_EXCHANGE_MODES = 0x002D;
    
    /**
     * 证书授权机构扩展 (TLS 1.3)
     */
    case CERTIFICATE_AUTHORITIES = 0x002F;
    
    /**
     * OID过滤器扩展 (TLS 1.3)
     */
    case OID_FILTERS = 0x0030;
    
    /**
     * 后握手认证扩展 (TLS 1.3)
     */
    case POST_HANDSHAKE_AUTH = 0x0031;
    
    /**
     * 证书签名算法扩展 (TLS 1.3)
     */
    case SIGNATURE_ALGORITHMS_CERT = 0x0032;
    
    /**
     * 密钥共享扩展 (TLS 1.3)
     */
    case KEY_SHARE = 0x0033;
}

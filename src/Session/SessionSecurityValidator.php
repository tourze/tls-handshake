<?php

namespace Tourze\TLSHandshake\Session;

/**
 * 会话安全参数验证器
 * 
 * 用于验证恢复会话的安全参数，确保不会降级安全性或使用不兼容的加密套件
 */
class SessionSecurityValidator
{
    /**
     * 验证TLS 1.2会话参数
     * 
     * @param TLSSession $session 要验证的会话
     * @param string $proposedCipherSuite 客户端提议的加密套件
     * @param int $proposedTlsVersion 客户端提议的TLS版本
     * @param bool $allowDowngrade 是否允许降级到较低的安全性，默认为false
     * @return bool 验证结果
     */
    public function validateTLS12Session(
        TLSSession $session,
        string $proposedCipherSuite,
        int $proposedTlsVersion,
        bool $allowDowngrade = false
    ): bool {
        // 验证加密套件
        if ($session->getCipherSuite() !== $proposedCipherSuite) {
            return false;
        }
        
        // 验证TLS版本（不允许降级，除非明确指定）
        if (!$allowDowngrade && $proposedTlsVersion < $session->getTlsVersion()) {
            return false;
        }
        
        return true;
    }
    
    /**
     * 验证TLS 1.3 PSK会话参数
     * 
     * @param TLS13PSKSession $session 要验证的PSK会话
     * @param string $proposedCipherSuite 客户端提议的加密套件
     * @param bool $fuzzyMatch 是否使用模糊匹配（如不区分大小写）
     * @return bool 验证结果
     */
    public function validateTLS13PSK(
        TLS13PSKSession $session,
        string $proposedCipherSuite,
        bool $fuzzyMatch = false
    ): bool {
        if ($fuzzyMatch) {
            return strcasecmp($session->getCipherSuite(), $proposedCipherSuite) === 0;
        }
        
        return $session->getCipherSuite() === $proposedCipherSuite;
    }
    
    /**
     * 根据服务器配置选项验证会话
     * 
     * @param SessionInterface $session 要验证的会话
     * @param array $serverOptions 服务器配置选项
     * @return bool 验证结果
     */
    public function validateSessionAgainstServerOptions(
        SessionInterface $session,
        array $serverOptions
    ): bool {
        // 获取服务器配置
        $allowDowngrade = $serverOptions['allowDowngrade'] ?? false;
        $requireExactMatch = $serverOptions['requireExactMatch'] ?? true;
        $minimumTlsVersion = $serverOptions['minimumTlsVersion'] ?? 0x0303; // 默认TLS 1.2
        $allowedCipherSuites = $serverOptions['allowedCipherSuites'] ?? [];
        
        // 检查TLS版本（如果适用）
        if ($session instanceof TLSSession) {
            if (!$allowDowngrade && $session->getTlsVersion() < $minimumTlsVersion) {
                return false;
            }
        }
        
        // 验证加密套件是否在允许列表中
        if (!empty($allowedCipherSuites)) {
            $sessionCipherSuite = $session->getCipherSuite();
            
            // 如果不是精确匹配，尝试模糊匹配
            if (!$requireExactMatch) {
                foreach ($allowedCipherSuites as $allowedSuite) {
                    if (strcasecmp($sessionCipherSuite, $allowedSuite) === 0) {
                        return true;
                    }
                }
                return false;
            }
            
            // 精确匹配
            return in_array($sessionCipherSuite, $allowedCipherSuites, true);
        }
        
        return true;
    }
} 
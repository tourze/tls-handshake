<?php

namespace Tourze\TLSHandshake\Handshake;

use Tourze\TLSHandshake\Extension\PostHandshakeAuthExtension;
use Tourze\TLSHandshake\Protocol\TLSVersion;

/**
 * TLS 1.3后握手认证管理器
 * 
 * 管理TLS 1.3连接的后握手认证过程
 * 在TLS 1.3中，不支持重协商，但可以通过后握手认证（Post-Handshake Authentication）来替代
 * 参考RFC 8446第4.6.2节
 */
class PostHandshakeAuthManager
{
    /**
     * 是否启用后握手认证
     */
    private bool $enabled = false;
    
    /**
     * 是否正在请求客户端证书
     */
    private bool $requestingCertificate = false;
    
    /**
     * 设置是否启用后握手认证
     * 
     * @param bool $enabled 是否启用
     * @return self
     */
    public function setEnabled(bool $enabled): self
    {
        $this->enabled = $enabled;
        return $this;
    }
    
    /**
     * 检查是否启用了后握手认证
     * 
     * @return bool 是否启用
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }
    
    /**
     * 请求客户端证书（服务器端使用）
     * 
     * @return self
     */
    public function requestClientCertificate(): self
    {
        $this->requestingCertificate = true;
        return $this;
    }
    
    /**
     * 重置证书请求状态
     * 
     * @return self
     */
    public function resetCertificateRequest(): self
    {
        $this->requestingCertificate = false;
        return $this;
    }
    
    /**
     * 检查是否正在请求客户端证书
     * 
     * @return bool 是否请求中
     */
    public function isRequestingCertificate(): bool
    {
        return $this->requestingCertificate;
    }
    
    /**
     * 创建后握手认证扩展（客户端使用）
     * 
     * @return PostHandshakeAuthExtension 后握手认证扩展
     */
    public function createPostHandshakeAuthExtension(): PostHandshakeAuthExtension
    {
        return new PostHandshakeAuthExtension();
    }
    
    /**
     * 检查是否支持指定TLS版本的后握手认证
     * 
     * @param TLSVersion $version TLS版本
     * @return bool 是否支持
     */
    public function isSupportedForVersion(TLSVersion $version): bool
    {
        // 后握手认证仅支持TLS 1.3
        return $version === TLSVersion::TLS_1_3;
    }
    
    /**
     * 处理客户端的后握手认证扩展
     * 
     * @param PostHandshakeAuthExtension|null $extension 客户端提供的扩展
     * @return bool 是否接受后握手认证
     */
    public function processClientPostHandshakeAuthExtension(?PostHandshakeAuthExtension $extension): bool
    {
        // 如果客户端提供了扩展，表示它支持后握手认证
        $this->enabled = $extension !== null;
        return $this->enabled;
    }
} 
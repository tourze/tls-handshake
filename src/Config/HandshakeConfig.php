<?php

namespace Tourze\TLSHandshake\Config;

/**
 * TLS握手配置实现
 */
class HandshakeConfig implements HandshakeConfigInterface
{
    /**
     * 是否为服务器模式
     *
     * @var bool
     */
    private bool $serverMode = false;
    
    /**
     * 支持的TLS版本列表
     *
     * @var array<string>
     */
    private array $supportedVersions = ['TLS 1.2', 'TLS 1.3'];
    
    /**
     * 支持的加密套件列表
     *
     * @var array<string>
     */
    private array $supportedCipherSuites = [
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        // TLS 1.3 加密套件
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
    ];
    
    /**
     * 证书文件路径
     *
     * @var string|null
     */
    private ?string $certificatePath = null;
    
    /**
     * 私钥文件路径
     *
     * @var string|null
     */
    private ?string $privateKeyPath = null;
    
    /**
     * 客户端证书文件路径
     *
     * @var string|null
     */
    private ?string $clientCertificatePath = null;
    
    /**
     * 客户端私钥文件路径
     *
     * @var string|null
     */
    private ?string $clientPrivateKeyPath = null;
    
    /**
     * 启用的扩展列表
     *
     * @var array<string, bool>
     */
    private array $enabledExtensions = [
        'server_name' => true,
        'supported_groups' => true,
        'ec_point_formats' => true,
        'signature_algorithms' => true,
        'application_layer_protocol_negotiation' => true,
        'status_request' => false,
        'signed_certificate_timestamp' => false,
        'key_share' => true,
        'pre_shared_key' => false,
        'early_data' => false,
    ];
    
    /**
     * {@inheritdoc}
     */
    public function setServerMode(bool $isServer): void
    {
        $this->serverMode = $isServer;
    }
    
    /**
     * {@inheritdoc}
     */
    public function isServerMode(): bool
    {
        return $this->serverMode;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setSupportedVersions(array $versions): void
    {
        $this->supportedVersions = $versions;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getSupportedVersions(): array
    {
        return $this->supportedVersions;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setSupportedCipherSuites(array $suites): void
    {
        $this->supportedCipherSuites = $suites;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getSupportedCipherSuites(): array
    {
        return $this->supportedCipherSuites;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setCertificatePath(?string $path): void
    {
        $this->certificatePath = $path;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getCertificatePath(): ?string
    {
        return $this->certificatePath;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setPrivateKeyPath(?string $path): void
    {
        $this->privateKeyPath = $path;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getPrivateKeyPath(): ?string
    {
        return $this->privateKeyPath;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setClientCertificatePath(?string $path): void
    {
        $this->clientCertificatePath = $path;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getClientCertificatePath(): ?string
    {
        return $this->clientCertificatePath;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setClientPrivateKeyPath(?string $path): void
    {
        $this->clientPrivateKeyPath = $path;
    }
    
    /**
     * {@inheritdoc}
     */
    public function getClientPrivateKeyPath(): ?string
    {
        return $this->clientPrivateKeyPath;
    }
    
    /**
     * {@inheritdoc}
     */
    public function enableExtension(string $extension): void
    {
        $this->enabledExtensions[$extension] = true;
    }
    
    /**
     * {@inheritdoc}
     */
    public function disableExtension(string $extension): void
    {
        $this->enabledExtensions[$extension] = false;
    }
    
    /**
     * {@inheritdoc}
     */
    public function isExtensionEnabled(string $extension): bool
    {
        return $this->enabledExtensions[$extension] ?? false;
    }
}

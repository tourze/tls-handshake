<?php

namespace Tourze\TLSHandshake\Config;

/**
 * TLS握手配置接口
 */
interface HandshakeConfigInterface
{
    /**
     * 设置是否为服务器模式
     *
     * @param bool $isServer 是否为服务器模式
     * @return void
     */
    public function setServerMode(bool $isServer): void;
    
    /**
     * 检查是否为服务器模式
     *
     * @return bool
     */
    public function isServerMode(): bool;
    
    /**
     * 设置支持的TLS版本列表
     *
     * @param array<string> $versions 支持的TLS版本列表
     * @return void
     */
    public function setSupportedVersions(array $versions): void;
    
    /**
     * 获取支持的TLS版本列表
     *
     * @return array<string>
     */
    public function getSupportedVersions(): array;
    
    /**
     * 设置支持的加密套件列表
     *
     * @param array<string> $suites 加密套件列表
     * @return void
     */
    public function setSupportedCipherSuites(array $suites): void;
    
    /**
     * 获取支持的加密套件列表
     *
     * @return array<string>
     */
    public function getSupportedCipherSuites(): array;
    
    /**
     * 设置证书文件路径
     *
     * @param string|null $path 证书文件路径
     * @return void
     */
    public function setCertificatePath(?string $path): void;
    
    /**
     * 获取证书文件路径
     *
     * @return string|null
     */
    public function getCertificatePath(): ?string;
    
    /**
     * 设置私钥文件路径
     *
     * @param string|null $path 私钥文件路径
     * @return void
     */
    public function setPrivateKeyPath(?string $path): void;
    
    /**
     * 获取私钥文件路径
     *
     * @return string|null
     */
    public function getPrivateKeyPath(): ?string;
    
    /**
     * 启用指定的TLS扩展
     *
     * @param string $extension 扩展名称
     * @return void
     */
    public function enableExtension(string $extension): void;
    
    /**
     * 禁用指定的TLS扩展
     *
     * @param string $extension 扩展名称
     * @return void
     */
    public function disableExtension(string $extension): void;
    
    /**
     * 检查指定的TLS扩展是否启用
     *
     * @param string $extension 扩展名称
     * @return bool
     */
    public function isExtensionEnabled(string $extension): bool;
}

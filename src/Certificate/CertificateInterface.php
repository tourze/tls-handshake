<?php

namespace Tourze\TLSHandshake\Certificate;

/**
 * 证书接口
 * 
 * 定义TLS证书的基本操作
 */
interface CertificateInterface
{
    /**
     * 获取证书原始数据
     * 
     * @return string 证书二进制数据
     */
    public function getRawData(): string;
    
    /**
     * 获取证书指纹
     * 
     * @param string $algorithm 哈希算法
     * @return string 证书指纹
     */
    public function getFingerprint(string $algorithm = 'sha256'): string;
    
    /**
     * 获取证书主题
     * 
     * @return array 证书主题信息
     */
    public function getSubject(): array;
    
    /**
     * 获取证书颁发者
     * 
     * @return array 证书颁发者信息
     */
    public function getIssuer(): array;
    
    /**
     * 获取证书有效期起始时间
     * 
     * @return int 时间戳
     */
    public function getValidFrom(): int;
    
    /**
     * 获取证书有效期结束时间
     * 
     * @return int 时间戳
     */
    public function getValidTo(): int;
    
    /**
     * 检查证书当前是否有效
     * 
     * @return bool 是否有效
     */
    public function isValid(): bool;
} 
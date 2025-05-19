<?php

namespace Tourze\TLSHandshake\Crypto\Certificate;

/**
 * 证书验证结果类
 */
class CertificateVerificationResult
{
    /**
     * 验证结果是否有效
     */
    private bool $valid;
    
    /**
     * 验证结果信息
     */
    private string $message;
    
    /**
     * 构造函数
     *
     * @param bool $valid 验证结果是否有效
     * @param string $message 验证结果信息
     */
    public function __construct(bool $valid, string $message)
    {
        $this->valid = $valid;
        $this->message = $message;
    }
    
    /**
     * 获取验证结果是否有效
     *
     * @return bool 验证结果是否有效
     */
    public function isValid(): bool
    {
        return $this->valid;
    }
    
    /**
     * 获取验证结果信息
     *
     * @return string 验证结果信息
     */
    public function getMessage(): string
    {
        return $this->message;
    }
} 
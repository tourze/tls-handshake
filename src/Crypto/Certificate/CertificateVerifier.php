<?php

namespace Tourze\TLSHandshake\Crypto\Certificate;

/**
 * 证书验证器抽象类
 */
abstract class CertificateVerifier
{
    /**
     * 验证证书的有效性
     *
     * @param string $certificate 待验证的证书
     * @param array<string> $certificateChain 证书链
     * @return CertificateVerificationResult 验证结果
     */
    abstract public function verify(string $certificate, array $certificateChain): CertificateVerificationResult;
    
    /**
     * 检查证书是否过期
     *
     * @param string $certificate 证书数据
     * @return bool 是否过期
     */
    protected function checkExpiration(string $certificate): bool
    {
        $certInfo = openssl_x509_parse($certificate);
        if (!$certInfo) {
            return false;
        }
        
        $now = time();
        return ($now >= $certInfo['validFrom_time_t'] && $now <= $certInfo['validTo_time_t']);
    }
    
    /**
     * 提取证书主题信息
     *
     * @param string $certificate 证书数据
     * @return array<string, string>|false 主题信息或失败返回false
     */
    protected function extractSubject(string $certificate)
    {
        $certInfo = openssl_x509_parse($certificate);
        if (!$certInfo || !isset($certInfo['subject'])) {
            return false;
        }
        
        return $certInfo['subject'];
    }
    
    /**
     * 提取证书颁发者信息
     *
     * @param string $certificate 证书数据
     * @return array<string, string>|false 颁发者信息或失败返回false
     */
    protected function extractIssuer(string $certificate)
    {
        $certInfo = openssl_x509_parse($certificate);
        if (!$certInfo || !isset($certInfo['issuer'])) {
            return false;
        }
        
        return $certInfo['issuer'];
    }
    
    /**
     * 验证证书链
     *
     * @param string $certificate 待验证的证书
     * @param array<string> $certificateChain 证书链
     * @return bool 验证是否成功
     */
    protected function verifyChain(string $certificate, array $certificateChain): bool
    {
        if (empty($certificateChain)) {
            return false;
        }
        
        // 创建证书存储
        $store = openssl_x509_store();
        
        // 添加所有中间证书到存储
        foreach ($certificateChain as $caCert) {
            $cert = openssl_x509_read($caCert);
            if ($cert) {
                openssl_x509_store_add_cert($store, $cert);
            }
        }
        
        // 验证证书
        $cert = openssl_x509_read($certificate);
        if (!$cert) {
            return false;
        }
        
        $result = openssl_x509_verify($cert, $store);
        
        return $result === 1;
    }
} 
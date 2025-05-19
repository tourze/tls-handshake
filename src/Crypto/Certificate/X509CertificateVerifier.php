<?php

namespace Tourze\TLSHandshake\Crypto\Certificate;

/**
 * X509证书验证器类
 */
class X509CertificateVerifier extends CertificateVerifier
{
    /**
     * 可信CA证书目录或文件路径
     */
    private ?string $caPath;
    
    /**
     * 构造函数
     *
     * @param string|null $caPath 可信CA证书目录或文件路径
     */
    public function __construct(?string $caPath = null)
    {
        $this->caPath = $caPath;
    }
    
    /**
     * 验证证书的有效性
     *
     * @param string $certificate 待验证的证书
     * @param array<string> $certificateChain 证书链
     * @return CertificateVerificationResult 验证结果
     */
    public function verify(string $certificate, array $certificateChain): CertificateVerificationResult
    {
        // 验证证书格式
        if (!$this->verifyFormat($certificate)) {
            return new CertificateVerificationResult(false, '证书格式无效');
        }
        
        // 验证证书是否过期
        if (!$this->checkExpiration($certificate)) {
            return new CertificateVerificationResult(false, '证书已过期');
        }
        
        // 验证证书链
        if (!empty($certificateChain) && !$this->verifyChain($certificate, $certificateChain)) {
            return new CertificateVerificationResult(false, '证书链验证失败');
        }
        
        // 验证可信CA签名
        if (!$this->verifyCATrust($certificate, $certificateChain)) {
            return new CertificateVerificationResult(false, '证书不受信任');
        }
        
        return new CertificateVerificationResult(true, '证书验证成功');
    }
    
    /**
     * 验证证书格式
     *
     * @param string $certificate 证书数据
     * @return bool 是否为有效的证书格式
     */
    private function verifyFormat(string $certificate): bool
    {
        return (bool)openssl_x509_read($certificate);
    }
    
    /**
     * 验证证书是否由可信CA签发
     *
     * @param string $certificate 证书数据
     * @param array<string> $certificateChain 证书链
     * @return bool 验证是否成功
     */
    private function verifyCATrust(string $certificate, array $certificateChain): bool
    {
        // 如果没有配置CA路径且没有提供证书链，不能验证信任
        if ($this->caPath === null && empty($certificateChain)) {
            return false;
        }
        
        $cert = openssl_x509_read($certificate);
        if (!$cert) {
            return false;
        }
        
        // 创建证书存储
        $store = openssl_x509_store();
        
        // 如果提供了CA路径，加载可信CA
        if ($this->caPath !== null) {
            openssl_x509_store_addcertificates($store, $this->caPath);
        }
        
        // 添加证书链
        foreach ($certificateChain as $caCert) {
            $chainCert = openssl_x509_read($caCert);
            if ($chainCert) {
                openssl_x509_store_add_cert($store, $chainCert);
            }
        }
        
        // 验证证书
        $result = openssl_x509_verify($cert, $store);
        
        return $result === 1;
    }
} 
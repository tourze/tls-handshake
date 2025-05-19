<?php

namespace Tourze\TLSHandshake\Crypto\Certificate;

use Tourze\TLSHandshake\Message\CertificateVerifyMessage;

/**
 * 证书验证消息生成器
 */
class CertificateVerifyGenerator
{
    /**
     * TLS 1.3客户端上下文字符串
     */
    private const TLS13_CLIENT_CONTEXT = "TLS 1.3, client CertificateVerify";
    
    /**
     * TLS 1.3服务器上下文字符串
     */
    private const TLS13_SERVER_CONTEXT = "TLS 1.3, server CertificateVerify";
    
    /**
     * 为TLS 1.2生成证书验证消息
     *
     * @param string $handshakeMessages 所有握手消息的串联
     * @param string $privateKey 私钥
     * @param int $signatureAlgorithm 签名算法
     * @return CertificateVerifyMessage 证书验证消息
     */
    public function generateTLS12VerifyMessage(string $handshakeMessages, string $privateKey, int $signatureAlgorithm): CertificateVerifyMessage
    {
        // 创建验证消息
        $message = new CertificateVerifyMessage();
        $message->setSignatureAlgorithm($signatureAlgorithm);
        
        // 根据签名算法获取哈希算法
        $hashAlgorithm = $this->getHashAlgorithmForSignature($signatureAlgorithm);
        
        // 计算握手消息哈希
        $handshakeHash = hash($hashAlgorithm, $handshakeMessages, true);
        
        // 生成签名
        $signature = $this->signData($handshakeHash, $privateKey, $signatureAlgorithm);
        $message->setSignature($signature);
        
        return $message;
    }
    
    /**
     * 为TLS 1.3生成证书验证消息
     *
     * @param string $handshakeContext 握手上下文
     * @param string $privateKey 私钥
     * @param int $signatureAlgorithm 签名算法
     * @param string $context 'client'或'server'
     * @return CertificateVerifyMessage 证书验证消息
     */
    public function generateTLS13VerifyMessage(string $handshakeContext, string $privateKey, int $signatureAlgorithm, string $context = 'client'): CertificateVerifyMessage
    {
        // 创建验证消息
        $message = new CertificateVerifyMessage();
        $message->setSignatureAlgorithm($signatureAlgorithm);
        
        // 构建TLS 1.3签名内容
        $contentToBeSigned = $this->constructTLS13SignatureContent($handshakeContext, $context);
        
        // 生成签名
        $signature = $this->signData($contentToBeSigned, $privateKey, $signatureAlgorithm);
        $message->setSignature($signature);
        
        return $message;
    }
    
    /**
     * 验证TLS 1.2证书验证消息
     *
     * @param CertificateVerifyMessage $message 证书验证消息
     * @param string $handshakeMessages 所有握手消息的串联
     * @param string $publicKey 公钥
     * @return bool 验证是否成功
     */
    public function verifyTLS12VerifyMessage(CertificateVerifyMessage $message, string $handshakeMessages, string $publicKey): bool
    {
        $signatureAlgorithm = $message->getSignatureAlgorithm();
        $signature = $message->getSignature();
        
        // 根据签名算法获取哈希算法
        $hashAlgorithm = $this->getHashAlgorithmForSignature($signatureAlgorithm);
        
        // 计算握手消息哈希
        $handshakeHash = hash($hashAlgorithm, $handshakeMessages, true);
        
        // 验证签名
        return $this->verifySignature($handshakeHash, $signature, $publicKey, $signatureAlgorithm);
    }
    
    /**
     * 验证TLS 1.3证书验证消息
     *
     * @param CertificateVerifyMessage $message 证书验证消息
     * @param string $handshakeContext 握手上下文
     * @param string $publicKey 公钥
     * @param string $context 'client'或'server'
     * @return bool 验证是否成功
     */
    public function verifyTLS13VerifyMessage(CertificateVerifyMessage $message, string $handshakeContext, string $publicKey, string $context = 'client'): bool
    {
        $signatureAlgorithm = $message->getSignatureAlgorithm();
        $signature = $message->getSignature();
        
        // 构建TLS 1.3签名内容
        $contentToBeSigned = $this->constructTLS13SignatureContent($handshakeContext, $context);
        
        // 验证签名
        return $this->verifySignature($contentToBeSigned, $signature, $publicKey, $signatureAlgorithm);
    }
    
    /**
     * 构建TLS 1.3签名内容
     *
     * @param string $handshakeContext 握手上下文
     * @param string $context 'client'或'server'
     * @return string 待签名内容
     */
    private function constructTLS13SignatureContent(string $handshakeContext, string $context = 'client'): string
    {
        // 生成32字节的全零填充
        $padding = str_repeat(chr(0x20), 64);
        
        // 选择上下文字符串
        $contextString = ($context === 'client') ? self::TLS13_CLIENT_CONTEXT : self::TLS13_SERVER_CONTEXT;
        
        // 计算握手上下文的哈希值
        $transcriptHash = hash('sha256', $handshakeContext, true);
        
        // 构建TLS 1.3签名内容：填充 + 上下文字符串 + 0x00 + 消息哈希
        return $padding . $contextString . chr(0x00) . $transcriptHash;
    }
    
    /**
     * 根据签名算法获取哈希算法
     *
     * @param int $signatureAlgorithm 签名算法
     * @return string 哈希算法名称
     */
    private function getHashAlgorithmForSignature(int $signatureAlgorithm): string
    {
        return match ($signatureAlgorithm) {
            0x0401, 0x0402, 0x0403, 0x0804 => 'sha256',
            0x0501, 0x0503, 0x0805 => 'sha384',
            0x0601, 0x0603, 0x0806 => 'sha512',
            default => 'sha256'
        };
    }
    
    /**
     * 使用私钥签名数据
     *
     * @param string $data 待签名数据
     * @param string $privateKey 私钥
     * @param int $signatureAlgorithm 签名算法
     * @return string 签名
     * @throws \RuntimeException 如果签名失败
     */
    protected function signData(string $data, string $privateKey, int $signatureAlgorithm): string
    {
        $key = openssl_pkey_get_private($privateKey);
        if (!$key) {
            throw new \RuntimeException('无效的私钥');
        }
        
        // 确定签名算法
        $opensslAlgorithm = $this->mapSignatureAlgorithmToOpenSSL($signatureAlgorithm);
        
        // 执行签名
        $signature = '';
        if (!openssl_sign($data, $signature, $key, $opensslAlgorithm)) {
            throw new \RuntimeException('签名失败: ' . openssl_error_string());
        }
        
        return $signature;
    }
    
    /**
     * 验证签名
     *
     * @param string $data 原始数据
     * @param string $signature 签名
     * @param string $publicKey 公钥
     * @param int $signatureAlgorithm 签名算法
     * @return bool 验证是否成功
     */
    protected function verifySignature(string $data, string $signature, string $publicKey, int $signatureAlgorithm): bool
    {
        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            return false;
        }
        
        // 确定签名算法
        $opensslAlgorithm = $this->mapSignatureAlgorithmToOpenSSL($signatureAlgorithm);
        
        // 执行验证
        $result = openssl_verify($data, $signature, $key, $opensslAlgorithm);
        
        return $result === 1;
    }
    
    /**
     * 将TLS签名算法映射到OpenSSL签名算法
     *
     * @param int $signatureAlgorithm TLS签名算法
     * @return int OpenSSL签名算法
     */
    private function mapSignatureAlgorithmToOpenSSL(int $signatureAlgorithm): int
    {
        return match ($signatureAlgorithm) {
            0x0401 => OPENSSL_ALGO_SHA256,    // rsa_pkcs1_sha256
            0x0501 => OPENSSL_ALGO_SHA384,    // rsa_pkcs1_sha384
            0x0601 => OPENSSL_ALGO_SHA512,    // rsa_pkcs1_sha512
            0x0403 => OPENSSL_ALGO_SHA256,    // ecdsa_secp256r1_sha256
            0x0503 => OPENSSL_ALGO_SHA384,    // ecdsa_secp384r1_sha384
            0x0603 => OPENSSL_ALGO_SHA512,    // ecdsa_secp521r1_sha512
            0x0804 => OPENSSL_ALGO_SHA256,    // rsa_pss_rsae_sha256
            0x0805 => OPENSSL_ALGO_SHA384,    // rsa_pss_rsae_sha384
            0x0806 => OPENSSL_ALGO_SHA512,    // rsa_pss_rsae_sha512
            default => OPENSSL_ALGO_SHA256    // 默认使用SHA256
        };
    }
} 
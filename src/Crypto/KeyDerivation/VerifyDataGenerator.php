<?php

declare(strict_types=1);

namespace Tourze\TLSHandshake\Crypto\KeyDerivation;

/**
 * 验证数据生成器
 * 用于生成握手消息的验证数据(Finished消息内容)
 */
class VerifyDataGenerator
{
    /**
     * TLS 1.2 PRF实例
     * 
     * @var TLS12PRF
     */
    private TLS12PRF $prf;
    
    /**
     * TLS 1.3 HKDF实例
     * 
     * @var TLS13HKDF
     */
    private TLS13HKDF $hkdf;
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->prf = new TLS12PRF();
        $this->hkdf = new TLS13HKDF();
    }
    
    /**
     * 生成TLS 1.2客户端验证数据
     * 
     * @param string $masterSecret 主密钥
     * @param string $handshakeMessages 握手消息
     * @return string 客户端验证数据
     */
    public function generateTLS12ClientVerifyData(string $masterSecret, string $handshakeMessages): string
    {
        // 计算所有握手消息的哈希
        $handshakeHash = hash('sha256', $handshakeMessages, true);
        
        // 使用PRF生成客户端验证数据
        return $this->prf->generateVerifyData($masterSecret, $handshakeHash, 'client finished');
    }
    
    /**
     * 生成TLS 1.2服务器验证数据
     * 
     * @param string $masterSecret 主密钥
     * @param string $handshakeMessages 握手消息
     * @return string 服务器验证数据
     */
    public function generateTLS12ServerVerifyData(string $masterSecret, string $handshakeMessages): string
    {
        // 计算所有握手消息的哈希
        $handshakeHash = hash('sha256', $handshakeMessages, true);
        
        // 使用PRF生成服务器验证数据
        return $this->prf->generateVerifyData($masterSecret, $handshakeHash, 'server finished');
    }
    
    /**
     * 生成TLS 1.3客户端验证数据
     * 
     * @param string $baseKey 基础密钥(通常是客户端握手流量密钥)
     * @param string $handshakeContext 握手上下文
     * @return string 客户端验证数据
     */
    public function generateTLS13ClientVerifyData(string $baseKey, string $handshakeContext): string
    {
        // TLS 1.3中验证数据计算与TLS 1.2不同
        
        // 从基础密钥派生完成密钥
        $finishedKey = $this->hkdf->expandLabel($baseKey, 'finished', '', 32);
        
        // 计算握手上下文的哈希
        $transcriptHash = hash('sha256', $handshakeContext, true);
        
        // 使用HMAC-SHA256计算验证数据
        return hash_hmac('sha256', $transcriptHash, $finishedKey, true);
    }
    
    /**
     * 生成TLS 1.3服务器验证数据
     * 
     * @param string $baseKey 基础密钥(通常是服务器握手流量密钥)
     * @param string $handshakeContext 握手上下文
     * @return string 服务器验证数据
     */
    public function generateTLS13ServerVerifyData(string $baseKey, string $handshakeContext): string
    {
        // 服务器端的验证数据计算与客户端相同，只是使用不同的基础密钥
        return $this->generateTLS13ClientVerifyData($baseKey, $handshakeContext);
    }
    
    /**
     * 验证TLS 1.2客户端提供的验证数据
     * 
     * @param string $verifyData 客户端提供的验证数据
     * @param string $masterSecret 主密钥
     * @param string $handshakeMessages 握手消息
     * @return bool 验证是否通过
     */
    public function verifyTLS12ClientData(string $verifyData, string $masterSecret, string $handshakeMessages): bool
    {
        $expected = $this->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);
        return hash_equals($expected, $verifyData);
    }
    
    /**
     * 验证TLS 1.2服务器提供的验证数据
     * 
     * @param string $verifyData 服务器提供的验证数据
     * @param string $masterSecret 主密钥
     * @param string $handshakeMessages 握手消息
     * @return bool 验证是否通过
     */
    public function verifyTLS12ServerData(string $verifyData, string $masterSecret, string $handshakeMessages): bool
    {
        $expected = $this->generateTLS12ServerVerifyData($masterSecret, $handshakeMessages);
        return hash_equals($expected, $verifyData);
    }
    
    /**
     * 验证TLS 1.3客户端提供的验证数据
     * 
     * @param string $verifyData 客户端提供的验证数据
     * @param string $baseKey 基础密钥
     * @param string $handshakeContext 握手上下文
     * @return bool 验证是否通过
     */
    public function verifyTLS13ClientData(string $verifyData, string $baseKey, string $handshakeContext): bool
    {
        $expected = $this->generateTLS13ClientVerifyData($baseKey, $handshakeContext);
        return hash_equals($expected, $verifyData);
    }
    
    /**
     * 验证TLS 1.3服务器提供的验证数据
     * 
     * @param string $verifyData 服务器提供的验证数据
     * @param string $baseKey 基础密钥
     * @param string $handshakeContext 握手上下文
     * @return bool 验证是否通过
     */
    public function verifyTLS13ServerData(string $verifyData, string $baseKey, string $handshakeContext): bool
    {
        $expected = $this->generateTLS13ServerVerifyData($baseKey, $handshakeContext);
        return hash_equals($expected, $verifyData);
    }
}

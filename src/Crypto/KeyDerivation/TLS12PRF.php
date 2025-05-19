<?php

declare(strict_types=1);

namespace Tourze\TLSHandshake\Crypto\KeyDerivation;

/**
 * TLS 1.2 PRF(伪随机函数)实现
 * 基于RFC 5246 Section 5
 * https://tools.ietf.org/html/rfc5246#section-5
 */
class TLS12PRF
{
    /**
     * 计算PRF结果
     * 
     * @param string $secret 密钥材料
     * @param string $label 标签
     * @param string $seed 种子
     * @param int $length 输出长度
     * @return string 生成的伪随机数据
     */
    public function compute(string $secret, string $label, string $seed, int $length): string
    {
        // TLS 1.2 使用 SHA-256 作为 P_hash 函数
        return $this->p_hash($secret, $label . $seed, $length, 'sha256');
    }
    
    /**
     * P_hash函数实现
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                         HMAC_hash(secret, A(2) + seed) +
     *                         HMAC_hash(secret, A(3) + seed) + ...
     * 
     * 其中：
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i-1))
     * 
     * @param string $secret 密钥材料
     * @param string $seed 种子
     * @param int $length 所需输出的字节数
     * @param string $hashAlgo 使用的哈希算法
     * @return string 生成的伪随机数据
     */
    private function p_hash(string $secret, string $seed, int $length, string $hashAlgo): string
    {
        $result = '';
        $a = $seed; // A(0) = seed
        
        $hashLength = match ($hashAlgo) {
            'sha256' => 32,
            'sha384' => 48,
            default => 32, // 默认使用SHA-256
        };
        
        $iterations = ceil($length / $hashLength);
        
        for ($i = 0; $i < $iterations; $i++) {
            $a = hash_hmac($hashAlgo, $a, $secret, true); // A(i) = HMAC_hash(secret, A(i-1))
            $result .= hash_hmac($hashAlgo, $a . $seed, $secret, true); // HMAC_hash(secret, A(i) + seed)
        }
        
        return substr($result, 0, $length);
    }
    
    /**
     * 生成TLS 1.2主密钥
     * 
     * @param string $premaster 预主密钥
     * @param string $clientRandom 客户端随机数
     * @param string $serverRandom 服务器随机数
     * @return string 48字节的主密钥
     */
    public function generateMasterSecret(string $premaster, string $clientRandom, string $serverRandom): string
    {
        $seed = $clientRandom . $serverRandom;
        return $this->compute($premaster, 'master secret', $seed, 48);
    }
    
    /**
     * 生成TLS 1.2密钥块
     * 
     * @param string $masterSecret 主密钥
     * @param string $clientRandom 客户端随机数
     * @param string $serverRandom 服务器随机数
     * @param int $length 所需密钥块长度
     * @return string 密钥块
     */
    public function generateKeyBlock(string $masterSecret, string $clientRandom, string $serverRandom, int $length): string
    {
        $seed = $serverRandom . $clientRandom;
        return $this->compute($masterSecret, 'key expansion', $seed, $length);
    }
    
    /**
     * 生成TLS 1.2验证数据
     * 
     * @param string $masterSecret 主密钥
     * @param string $handshakeHash 握手消息哈希
     * @param string $label 客户端("client finished")或服务器("server finished")标签
     * @return string 12字节的验证数据
     */
    public function generateVerifyData(string $masterSecret, string $handshakeHash, string $label): string
    {
        return $this->compute($masterSecret, $label, $handshakeHash, 12);
    }
}

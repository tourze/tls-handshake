<?php

declare(strict_types=1);

namespace Tourze\TLSHandshake\Crypto\KeyDerivation;

/**
 * TLS 1.3 HKDF(基于HMAC的密钥派生函数)实现
 * 基于RFC 8446 Section 7.1
 * https://tools.ietf.org/html/rfc8446#section-7.1
 */
class TLS13HKDF
{
    /**
     * 默认哈希算法
     * 
     * @var string
     */
    private const DEFAULT_HASH = 'sha256';
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        // 不使用CryptoFactory提供的HKDF，改为直接进行HKDF计算
        // 后续可能会替换为使用CryptoFactory
    }
    
    /**
     * HKDF-Extract函数
     * 
     * @param string $salt 盐值
     * @param string $ikm 输入密钥材料
     * @return string 伪随机密钥(PRK)
     */
    public function extract(string $salt, string $ikm): string
    {
        // 如果不使用crypto包中的HKDF，直接使用PHP内置hash_hmac
        return hash_hmac(self::DEFAULT_HASH, $ikm, $salt, true);
    }
    
    /**
     * HKDF-Expand函数
     * 
     * @param string $prk 伪随机密钥
     * @param string $info 上下文信息
     * @param int $length 输出长度
     * @return string 输出密钥材料
     */
    public function expand(string $prk, string $info, int $length): string
    {
        $result = '';
        $t = '';
        $counter = 1;
        $hashLen = match (self::DEFAULT_HASH) {
            'sha256' => 32,
            'sha384' => 48,
            default => 32,
        };
        
        while (strlen($result) < $length) {
            $t = hash_hmac(self::DEFAULT_HASH, $t . $info . chr($counter), $prk, true);
            $result .= $t;
            $counter++;
        }
        
        return substr($result, 0, $length);
    }
    
    /**
     * HKDF-Expand-Label函数
     * 
     * @param string $secret 密钥
     * @param string $label 标签
     * @param string $context 上下文(通常是握手哈希)
     * @param int $length 输出长度
     * @return string 导出的密钥材料
     */
    public function expandLabel(string $secret, string $label, string $context, int $length): string
    {
        // TLS 1.3 HkdfLabel结构:
        // struct {
        //     uint16 length;
        //     opaque label<7..255>;
        //     opaque context<0..255>;
        // } HkdfLabel;
        
        $labelPrefix = 'tls13 '; // TLS 1.3 要求前缀
        $hkdfLabel = pack('n', $length) .                          // uint16 length
                     chr(strlen($labelPrefix . $label)) . ($labelPrefix . $label) . // opaque label<7..255>
                     chr(strlen($context)) . $context;              // opaque context<0..255>
        
        return $this->expand($secret, $hkdfLabel, $length);
    }
    
    /**
     * Derive-Secret函数
     * 
     * @param string $secret 密钥
     * @param string $label 标签
     * @param string $messages 消息内容(通常是之前所有握手消息的拼接)
     * @return string 导出的密钥
     */
    public function deriveSecret(string $secret, string $label, string $messages): string
    {
        // 计算消息哈希
        $transcriptHash = '';
        if (empty($messages)) {
            // 如果消息为空，使用空字符串的哈希值
            $transcriptHash = hash(self::DEFAULT_HASH, '', true);
        } else {
            $transcriptHash = hash(self::DEFAULT_HASH, $messages, true);
        }
        
        // 默认输出长度与哈希算法相同
        $length = match (self::DEFAULT_HASH) {
            'sha256' => 32,
            'sha384' => 48,
            default => 32,
        };
        
        return $this->expandLabel($secret, $label, $transcriptHash, $length);
    }
    
    /**
     * 派生早期密钥
     * 
     * @param string $psk 预共享密钥
     * @return string 早期密钥
     */
    public function deriveEarlySecret(string $psk = ''): string
    {
        // 如果没有提供PSK，使用全0填充的哈希长度字符串
        if (empty($psk)) {
            $psk = str_repeat("\0", 32); // SHA-256 长度
        }
        
        $salt = str_repeat("\0", 32); // 初始盐值为全0填充
        return $this->extract($salt, $psk);
    }
    
    /**
     * 从给定的早期密钥派生握手密钥
     * 
     * @param string $earlySecret 早期密钥
     * @param string $sharedSecret 共享密钥(通常是密钥交换的结果)
     * @return string 握手密钥
     */
    public function deriveHandshakeSecret(string $earlySecret, string $sharedSecret): string
    {
        // 派生派生密钥
        $derivedSecret = $this->deriveSecret($earlySecret, 'derived', '');
        
        // 使用派生密钥作为盐值提取握手密钥
        return $this->extract($derivedSecret, $sharedSecret);
    }
    
    /**
     * 从给定的握手密钥派生主密钥
     * 
     * @param string $handshakeSecret 握手密钥
     * @return string 主密钥
     */
    public function deriveMasterSecret(string $handshakeSecret): string
    {
        // 派生派生密钥
        $derivedSecret = $this->deriveSecret($handshakeSecret, 'derived', '');
        
        // 使用派生密钥作为盐值提取主密钥(使用0作为IKM)
        $zeroKey = str_repeat("\0", 32); // SHA-256 长度
        return $this->extract($derivedSecret, $zeroKey);
    }
}

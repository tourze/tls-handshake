<?php

namespace Tourze\TLSHandshake\Crypto\KeyExchange;

/**
 * RSA密钥交换实现
 * 
 * 参考RFC 5246 - TLS 1.2
 */
class RSAKeyExchange implements KeyExchangeInterface
{
    /**
     * 服务器公钥
     * 
     * @var string
     */
    private string $serverPublicKey = '';
    
    /**
     * 客户端预主密钥
     * 
     * @var string
     */
    private string $preMasterSecret = '';
    
    /**
     * 设置服务器公钥
     * 
     * @param string $publicKey 服务器公钥（PEM或DER格式）
     * @return self
     */
    public function setServerPublicKey(string $publicKey): self
    {
        $this->serverPublicKey = $publicKey;
        return $this;
    }
    
    /**
     * 获取服务器公钥
     * 
     * @return string 服务器公钥
     */
    public function getServerPublicKey(): string
    {
        return $this->serverPublicKey;
    }
    
    /**
     * 生成预主密钥
     * 
     * 在RSA密钥交换中，客户端生成随机的预主密钥
     * 
     * @param int $version TLS版本（用于放入预主密钥的前两个字节）
     * @return string 生成的预主密钥
     */
    public function generatePreMasterSecret(int $version): string
    {
        // 预主密钥格式：[客户端版本(2字节)][随机字节(46字节)]
        $clientVersion = pack('n', $version);
        
        // 生成46字节的随机数据
        $randomBytes = random_bytes(46);
        
        $this->preMasterSecret = $clientVersion . $randomBytes;
        return $this->preMasterSecret;
    }
    
    /**
     * 加密预主密钥
     * 
     * 使用服务器公钥加密预主密钥
     * 
     * @return string 加密后的预主密钥
     * @throws \RuntimeException 如果加密失败
     */
    public function encryptPreMasterSecret(): string
    {
        if (empty($this->preMasterSecret)) {
            throw new \RuntimeException('Pre-master secret not generated');
        }
        
        if (empty($this->serverPublicKey)) {
            throw new \RuntimeException('Server public key not set');
        }
        
        // 加载服务器公钥
        $publicKey = openssl_pkey_get_public($this->serverPublicKey);
        if ($publicKey === false) {
            throw new \RuntimeException('Failed to load server public key: ' . openssl_error_string());
        }
        
        // 使用服务器公钥加密预主密钥
        $encrypted = '';
        $result = openssl_public_encrypt($this->preMasterSecret, $encrypted, $publicKey, OPENSSL_PKCS1_PADDING);
        
        if ($result === false) {
            throw new \RuntimeException('Failed to encrypt pre-master secret: ' . openssl_error_string());
        }
        
        return $encrypted;
    }
    
    /**
     * 解密预主密钥（服务器端）
     * 
     * @param string $encryptedPreMasterSecret 加密的预主密钥
     * @param string $privateKey 服务器私钥
     * @return string 解密后的预主密钥
     * @throws \RuntimeException 如果解密失败
     */
    public function decryptPreMasterSecret(string $encryptedPreMasterSecret, string $privateKey): string
    {
        // 加载服务器私钥
        $key = openssl_pkey_get_private($privateKey);
        if ($key === false) {
            throw new \RuntimeException('Failed to load server private key: ' . openssl_error_string());
        }
        
        // 解密预主密钥
        $decrypted = '';
        $result = openssl_private_decrypt($encryptedPreMasterSecret, $decrypted, $key, OPENSSL_PKCS1_PADDING);
        
        if ($result === false) {
            throw new \RuntimeException('Failed to decrypt pre-master secret: ' . openssl_error_string());
        }
        
        $this->preMasterSecret = $decrypted;
        return $decrypted;
    }
    
    /**
     * 获取预主密钥
     * 
     * @return string 预主密钥
     */
    public function getPreMasterSecret(): string
    {
        return $this->preMasterSecret;
    }
} 
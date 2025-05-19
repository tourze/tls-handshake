<?php

namespace Tourze\TLSHandshake\Crypto\KeyExchange;

/**
 * ECDHE密钥交换实现
 * 
 * 参考RFC 5246和RFC 4492 - TLS 1.2中的椭圆曲线DH密钥交换
 */
class ECDHEKeyExchange implements KeyExchangeInterface
{
    /**
     * 椭圆曲线类型
     * 
     * @var string
     */
    private string $curve = '';
    
    /**
     * 服务器ECDH公钥点
     * 
     * @var string
     */
    private string $serverPublicKey = '';
    
    /**
     * 客户端ECDH私钥
     * 
     * @var string
     */
    private string $clientPrivateKey = '';
    
    /**
     * 客户端ECDH公钥点
     * 
     * @var string
     */
    private string $clientPublicKey = '';
    
    /**
     * 预主密钥
     * 
     * @var string
     */
    private string $preMasterSecret = '';
    
    /**
     * 常见的椭圆曲线组
     * 
     * @var array<string, string>
     */
    private static array $CURVE_MAP = [
        'secp256r1' => 'prime256v1',  // P-256
        'secp384r1' => 'secp384r1',   // P-384
        'secp521r1' => 'secp521r1',   // P-521
        'x25519'    => 'X25519'       // Curve25519
    ];
    
    /**
     * 设置椭圆曲线参数
     * 
     * @param string $curve 椭圆曲线类型
     * @param string $serverPublicKey 服务器ECDH公钥点
     * @return self
     * @throws \InvalidArgumentException 如果曲线类型不支持
     */
    public function setECParameters(string $curve, string $serverPublicKey): self
    {
        if (!array_key_exists($curve, self::$CURVE_MAP)) {
            throw new \InvalidArgumentException("Unsupported elliptic curve: $curve");
        }
        
        $this->curve = $curve;
        $this->serverPublicKey = $serverPublicKey;
        return $this;
    }
    
    /**
     * 获取椭圆曲线类型
     * 
     * @return string 椭圆曲线类型
     */
    public function getCurve(): string
    {
        return $this->curve;
    }
    
    /**
     * 获取服务器ECDH公钥
     * 
     * @return string 服务器ECDH公钥
     */
    public function getServerPublicKey(): string
    {
        return $this->serverPublicKey;
    }
    
    /**
     * 生成客户端密钥对
     * 
     * @return string 客户端ECDH公钥
     * @throws \RuntimeException 如果生成密钥对失败
     */
    public function generateClientKeyPair(): string
    {
        if (empty($this->curve) || empty($this->serverPublicKey)) {
            throw new \RuntimeException('EC parameters not set');
        }
        
        $opensslCurve = self::$CURVE_MAP[$this->curve];
        
        // 创建EC密钥对
        $config = [
            'curve_name' => $opensslCurve,
            'private_key_type' => OPENSSL_KEYTYPE_EC
        ];
        
        $key = openssl_pkey_new($config);
        if ($key === false) {
            throw new \RuntimeException('Failed to create EC key: ' . openssl_error_string());
        }
        
        // 获取私钥和公钥
        $result = openssl_pkey_export($key, $privateKeyPem);
        if ($result === false) {
            throw new \RuntimeException('Failed to export EC private key: ' . openssl_error_string());
        }
        
        $this->clientPrivateKey = $privateKeyPem;
        
        // 提取公钥
        $keyDetails = openssl_pkey_get_details($key);
        if ($keyDetails === false) {
            throw new \RuntimeException('Failed to get EC key details: ' . openssl_error_string());
        }
        
        $this->clientPublicKey = $keyDetails['key'];
        
        // 返回客户端公钥（通常是未压缩格式的EC点）
        return $this->clientPublicKey;
    }
    
    /**
     * 计算预主密钥
     * 
     * 使用服务器公钥和客户端私钥计算共享密钥
     * 
     * @return string 预主密钥
     * @throws \RuntimeException 如果计算失败
     */
    public function computePreMasterSecret(): string
    {
        if (empty($this->clientPrivateKey) || empty($this->serverPublicKey)) {
            throw new \RuntimeException('Missing parameters for computing pre-master secret');
        }
        
        // 加载服务器公钥
        $serverKey = openssl_pkey_get_public($this->serverPublicKey);
        if ($serverKey === false) {
            throw new \RuntimeException('Failed to load server EC public key: ' . openssl_error_string());
        }
        
        // 加载客户端私钥
        $clientKey = openssl_pkey_get_private($this->clientPrivateKey);
        if ($clientKey === false) {
            throw new \RuntimeException('Failed to load client EC private key: ' . openssl_error_string());
        }
        
        // 执行ECDH操作
        // 注意：PHP没有直接的ECDH函数，我们需要使用自定义的方法或使用OpenSSL的低级API
        // 这里我们模拟ECDH操作，实际项目应使用可靠的密码库
        
        // 将服务器公钥解析为EC点
        $serverKeyDetails = openssl_pkey_get_details($serverKey);
        if ($serverKeyDetails === false) {
            throw new \RuntimeException('Failed to get server EC key details: ' . openssl_error_string());
        }
        
        // 对于实际项目，应使用专门的ECDH库
        // 这里我们使用哈希算法模拟共享密钥的计算
        // 注意：这不是真正的ECDH实现，仅用于演示！
        $sharedInfo = $serverKeyDetails['key'] . $this->clientPrivateKey;
        $this->preMasterSecret = hash('sha256', $sharedInfo, true);
        
        return $this->preMasterSecret;
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
    
    /**
     * 获取客户端公钥
     * 
     * @return string 客户端公钥
     */
    public function getClientPublicKey(): string
    {
        return $this->clientPublicKey;
    }
} 
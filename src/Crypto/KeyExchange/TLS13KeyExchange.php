<?php

namespace Tourze\TLSHandshake\Crypto\KeyExchange;

/**
 * TLS 1.3密钥交换实现
 * 
 * 参考RFC 8446 - TLS 1.3密钥交换机制
 * TLS 1.3中的密钥交换机制主要基于ECDHE
 */
class TLS13KeyExchange implements KeyExchangeInterface
{
    /**
     * 密钥共享组类型
     * 
     * @var string
     */
    private string $group = '';
    
    /**
     * 支持的组类型
     * 
     * @var array<string, string>
     */
    private static array $GROUP_MAP = [
        'x25519'    => 'X25519',       // Curve25519
        'x448'      => 'X448',         // Curve448
        'secp256r1' => 'prime256v1',   // P-256
        'secp384r1' => 'secp384r1',    // P-384
        'secp521r1' => 'secp521r1'     // P-521
    ];
    
    /**
     * 服务器密钥共享数据
     * 
     * @var string
     */
    private string $serverKeyShare = '';
    
    /**
     * 客户端私钥
     * 
     * @var string
     */
    private string $clientPrivateKey = '';
    
    /**
     * 客户端密钥共享数据
     * 
     * @var string
     */
    private string $clientKeyShare = '';
    
    /**
     * 共享密钥
     * 
     * @var string
     */
    private string $sharedSecret = '';
    
    /**
     * 设置密钥共享参数
     * 
     * @param string $group 密钥共享组类型
     * @param string $serverKeyShare 服务器密钥共享数据
     * @return self
     * @throws \InvalidArgumentException 如果组类型不支持
     */
    public function setKeyShareParameters(string $group, string $serverKeyShare): self
    {
        if (!array_key_exists($group, self::$GROUP_MAP)) {
            throw new \InvalidArgumentException("Unsupported key share group: $group");
        }
        
        $this->group = $group;
        $this->serverKeyShare = $serverKeyShare;
        return $this;
    }
    
    /**
     * 获取组类型
     * 
     * @return string 组类型
     */
    public function getGroup(): string
    {
        return $this->group;
    }
    
    /**
     * 获取服务器密钥共享数据
     * 
     * @return string 服务器密钥共享数据
     */
    public function getServerKeyShare(): string
    {
        return $this->serverKeyShare;
    }
    
    /**
     * 生成客户端密钥共享
     * 
     * @return string 客户端密钥共享数据
     * @throws \RuntimeException 如果生成失败
     */
    public function generateKeyShare(): string
    {
        if (empty($this->group)) {
            throw new \RuntimeException('Key share group not set');
        }
        
        $opensslGroup = self::$GROUP_MAP[$this->group];
        
        // X25519和X448特殊处理
        if ($this->group === 'x25519' || $this->group === 'x448') {
            // 对于这些曲线，我们使用定制的实现
            // 注意：实际项目中应使用专门的库
            if ($this->group === 'x25519') {
                // 生成32字节随机私钥
                $this->clientPrivateKey = random_bytes(32);
                
                // 在实际项目中，这里应调用X25519库函数
                // 模拟生成公钥（实际中应使用专门的库）
                $this->clientKeyShare = hash('sha256', $this->clientPrivateKey, true);
            } else { // x448
                // 生成56字节随机私钥
                $this->clientPrivateKey = random_bytes(56);
                
                // 模拟公钥
                $this->clientKeyShare = hash('sha512', $this->clientPrivateKey, true);
            }
        } else {
            // 对于标准EC曲线，使用OpenSSL
            $config = [
                'curve_name' => $opensslGroup,
                'private_key_type' => OPENSSL_KEYTYPE_EC
            ];
            
            $key = openssl_pkey_new($config);
            if ($key === false) {
                throw new \RuntimeException('Failed to create EC key: ' . openssl_error_string());
            }
            
            // 导出私钥
            $result = openssl_pkey_export($key, $privateKeyPem);
            if ($result === false) {
                throw new \RuntimeException('Failed to export EC private key: ' . openssl_error_string());
            }
            
            $this->clientPrivateKey = $privateKeyPem;
            
            // 获取公钥信息
            $keyDetails = openssl_pkey_get_details($key);
            if ($keyDetails === false) {
                throw new \RuntimeException('Failed to get EC key details: ' . openssl_error_string());
            }
            
            // 提取公钥点
            $this->clientKeyShare = $keyDetails['key'];
        }
        
        return $this->clientKeyShare;
    }
    
    /**
     * 计算共享密钥
     * 
     * @return string 共享密钥
     * @throws \RuntimeException 如果计算失败
     */
    public function computeSharedSecret(): string
    {
        if (empty($this->clientPrivateKey) || empty($this->serverKeyShare)) {
            throw new \RuntimeException('Missing parameters for computing shared secret');
        }
        
        // X25519和X448特殊处理
        if ($this->group === 'x25519' || $this->group === 'x448') {
            // 对于这些曲线，需要专门的库
            // 这里简化实现，实际项目应使用正确的密码学实现
            $sharedInfo = $this->serverKeyShare . $this->clientPrivateKey;
            if ($this->group === 'x25519') {
                $this->sharedSecret = hash('sha256', $sharedInfo, true);
            } else { // x448
                $this->sharedSecret = hash('sha512', $sharedInfo, true);
            }
        } else {
            // 对于标准EC曲线，使用OpenSSL
            // 加载服务器公钥
            $serverKey = openssl_pkey_get_public($this->serverKeyShare);
            if ($serverKey === false) {
                throw new \RuntimeException('Failed to load server EC public key: ' . openssl_error_string());
            }
            
            // 加载客户端私钥
            $clientKey = openssl_pkey_get_private($this->clientPrivateKey);
            if ($clientKey === false) {
                throw new \RuntimeException('Failed to load client EC private key: ' . openssl_error_string());
            }
            
            // 执行ECDH操作
            // 注意：实际项目中应使用专门的ECDH库
            $serverKeyDetails = openssl_pkey_get_details($serverKey);
            if ($serverKeyDetails === false) {
                throw new \RuntimeException('Failed to get server EC key details: ' . openssl_error_string());
            }
            
            // 模拟共享密钥计算
            // 注意：这不是真正的ECDH实现！
            $sharedInfo = $serverKeyDetails['key'] . $this->clientPrivateKey;
            $this->sharedSecret = hash('sha256', $sharedInfo, true);
        }
        
        return $this->sharedSecret;
    }
    
    /**
     * 获取预主密钥
     * 
     * 在TLS 1.3中，共享密钥就是预主密钥
     * 
     * @return string 预主密钥
     */
    public function getPreMasterSecret(): string
    {
        return $this->sharedSecret;
    }
    
    /**
     * 获取客户端密钥共享数据
     * 
     * @return string 客户端密钥共享数据
     */
    public function getClientKeyShare(): string
    {
        return $this->clientKeyShare;
    }
    
    /**
     * 格式化密钥共享扩展数据
     * 
     * 用于在ClientHello扩展中发送
     * 
     * @return string 格式化的密钥共享扩展数据
     * @throws \RuntimeException 如果密钥共享未生成
     */
    public function formatKeyShareExtension(): string
    {
        if (empty($this->clientKeyShare)) {
            throw new \RuntimeException('Client key share not generated');
        }
        
        // 获取组ID
        $groupId = $this->getGroupId($this->group);
        
        // 组ID（2字节）+ 密钥共享长度（2字节）+ 密钥共享数据
        $keyShareLength = pack('n', strlen($this->clientKeyShare));
        return pack('n', $groupId) . $keyShareLength . $this->clientKeyShare;
    }
    
    /**
     * 获取组ID
     * 
     * @param string $group 组名称
     * @return int 组ID
     * @throws \InvalidArgumentException 如果组不支持
     */
    private function getGroupId(string $group): int
    {
        $groupMap = [
            'secp256r1' => 23,   // 0x0017
            'secp384r1' => 24,   // 0x0018
            'secp521r1' => 25,   // 0x0019
            'x25519'    => 29,   // 0x001D
            'x448'      => 30    // 0x001E
        ];
        
        if (!isset($groupMap[$group])) {
            throw new \InvalidArgumentException("Unknown group: $group");
        }
        
        return $groupMap[$group];
    }
} 
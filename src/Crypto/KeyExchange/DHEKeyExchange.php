<?php

namespace Tourze\TLSHandshake\Crypto\KeyExchange;

/**
 * DHE密钥交换实现
 * 
 * 参考RFC 5246 - TLS 1.2中的DHE密钥交换
 */
class DHEKeyExchange implements KeyExchangeInterface
{
    /**
     * DH素数p
     * 
     * @var string
     */
    private string $p = '';
    
    /**
     * DH生成元g
     * 
     * @var string
     */
    private string $g = '';
    
    /**
     * 服务器DH公钥Ys
     * 
     * @var string
     */
    private string $serverPublicKey = '';
    
    /**
     * 客户端DH私钥Xc
     * 
     * @var string
     */
    private string $clientPrivateKey = '';
    
    /**
     * 客户端DH公钥Yc
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
     * 设置DH参数
     * 
     * @param string $p 素数p（大整数，通常为512-2048位）
     * @param string $g 生成元g（通常为2或5）
     * @param string $serverPublicKey 服务器DH公钥
     * @return self
     */
    public function setDHParameters(string $p, string $g, string $serverPublicKey): self
    {
        $this->p = $p;
        $this->g = $g;
        $this->serverPublicKey = $serverPublicKey;
        return $this;
    }
    
    /**
     * 获取DH素数p
     * 
     * @return string DH素数p
     */
    public function getP(): string
    {
        return $this->p;
    }
    
    /**
     * 获取DH生成元g
     * 
     * @return string DH生成元g
     */
    public function getG(): string
    {
        return $this->g;
    }
    
    /**
     * 获取服务器DH公钥
     * 
     * @return string 服务器DH公钥
     */
    public function getServerPublicKey(): string
    {
        return $this->serverPublicKey;
    }
    
    /**
     * 生成客户端密钥对
     * 
     * @return string 客户端DH公钥
     * @throws \RuntimeException 如果生成密钥对失败
     */
    public function generateClientKeyPair(): string
    {
        if (empty($this->p) || empty($this->g) || empty($this->serverPublicKey)) {
            throw new \RuntimeException('DH parameters not set');
        }
        
        // 使用OpenSSL创建DH参数
        $dhParameters = [
            'p' => $this->hexToBin($this->p),
            'g' => $this->hexToBin($this->g)
        ];
        
        // 创建DH资源
        $dh = openssl_pkey_new([
            'dh' => $dhParameters
        ]);
        
        if ($dh === false) {
            throw new \RuntimeException('Failed to create DH key: ' . openssl_error_string());
        }
        
        // 获取私钥和公钥
        $keyData = openssl_pkey_get_details($dh);
        if ($keyData === false) {
            throw new \RuntimeException('Failed to get DH key details: ' . openssl_error_string());
        }
        
        // 客户端私钥和公钥
        $this->clientPrivateKey = $this->binToHex($keyData['dh']['priv_key']);
        $this->clientPublicKey = $this->binToHex($keyData['dh']['pub_key']);
        
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
        if (empty($this->clientPrivateKey) || empty($this->serverPublicKey) || empty($this->p)) {
            throw new \RuntimeException('Missing parameters for computing pre-master secret');
        }
        
        // 这里应该使用服务器公钥和客户端私钥计算DH共享密钥
        // 由于PHP没有直接提供DH计算函数，我们使用openssl_dh_compute_key
        
        // 创建DH参数
        $dhParameters = [
            'p' => $this->hexToBin($this->p),
            'g' => $this->hexToBin($this->g),
            'priv_key' => $this->hexToBin($this->clientPrivateKey)
        ];
        
        // 计算共享密钥: (serverPublicKey^clientPrivateKey) mod p
        $serverKey = $this->hexToBin($this->serverPublicKey);
        
        // 使用GMP库进行大整数运算
        if (function_exists('gmp_init')) {
            $p = gmp_init('0x' . $this->p, 16);
            $g = gmp_init('0x' . $this->g, 16);
            $serverKey = gmp_init('0x' . $this->serverPublicKey, 16);
            $clientKey = gmp_init('0x' . $this->clientPrivateKey, 16);
            
            // 计算 (serverKey^clientKey) mod p
            $sharedSecret = gmp_powm($serverKey, $clientKey, $p);
            $this->preMasterSecret = $this->binToHex(gmp_export($sharedSecret));
        } else {
            // 备用方法：使用OpenSSL的DH计算
            $privateKey = openssl_pkey_new([
                'dh' => $dhParameters
            ]);
            
            if ($privateKey === false) {
                throw new \RuntimeException('Failed to create DH key for computation: ' . openssl_error_string());
            }
            
            $sharedSecret = openssl_dh_compute_key($serverKey, $privateKey);
            if ($sharedSecret === false) {
                throw new \RuntimeException('Failed to compute DH shared secret: ' . openssl_error_string());
            }
            
            $this->preMasterSecret = $this->binToHex($sharedSecret);
        }
        
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
    
    /**
     * 将十六进制字符串转换为二进制数据
     * 
     * @param string $hex 十六进制字符串
     * @return string 二进制数据
     */
    private function hexToBin(string $hex): string
    {
        if (substr($hex, 0, 2) === '0x') {
            $hex = substr($hex, 2);
        }
        
        $result = '';
        for ($i = 0; $i < strlen($hex); $i += 2) {
            $result .= chr(hexdec(substr($hex, $i, 2)));
        }
        
        return $result;
    }
    
    /**
     * 将二进制数据转换为十六进制字符串
     * 
     * @param string $bin 二进制数据
     * @return string 十六进制字符串
     */
    private function binToHex(string $bin): string
    {
        $result = '';
        for ($i = 0; $i < strlen($bin); $i++) {
            $result .= bin2hex($bin[$i]);
        }
        
        return $result;
    }
} 
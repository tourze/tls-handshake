<?php

namespace Tourze\TLSHandshake\Crypto;

use Tourze\TLSHandshake\Protocol\TLSVersion;

/**
 * TLS加密套件协商器
 * 
 * 负责选择客户端和服务器都支持的最佳加密套件
 */
class CipherSuiteNegotiator
{
    /**
     * 服务器支持的加密套件列表
     * 
     * @var array<int>
     */
    private array $serverCipherSuites = [];
    
    /**
     * 构造函数
     * 
     * @param TLSVersion $version TLS协议版本
     * @param array<int>|null $customCipherSuites 自定义加密套件列表（可选）
     */
    public function __construct(
        private TLSVersion $version,
        ?array $customCipherSuites = null
    ) {
        // 如果提供了自定义加密套件，则使用它们
        if ($customCipherSuites !== null) {
            $this->serverCipherSuites = $customCipherSuites;
        } else {
            // 否则根据TLS版本使用推荐的加密套件
            $this->serverCipherSuites = match($version) {
                TLSVersion::TLS_1_3 => CipherSuite::getRecommendedTLS13CipherSuites(),
                default => CipherSuite::getRecommendedTLS12CipherSuites(),
            };
        }
    }
    
    /**
     * 获取TLS版本
     * 
     * @return TLSVersion TLS版本
     */
    public function getVersion(): TLSVersion
    {
        return $this->version;
    }
    
    /**
     * 设置TLS版本
     * 
     * @param TLSVersion $version TLS版本
     * @return self
     */
    public function setVersion(TLSVersion $version): self
    {
        $this->version = $version;
        return $this;
    }
    
    /**
     * 获取服务器支持的加密套件列表
     * 
     * @return array<int> 加密套件列表
     */
    public function getServerCipherSuites(): array
    {
        return $this->serverCipherSuites;
    }
    
    /**
     * 设置服务器支持的加密套件列表
     * 
     * @param array<int> $cipherSuites 加密套件列表
     * @return self
     */
    public function setServerCipherSuites(array $cipherSuites): self
    {
        $this->serverCipherSuites = $cipherSuites;
        return $this;
    }
    
    /**
     * 添加服务器支持的加密套件
     * 
     * @param int $cipherSuite 加密套件
     * @return self
     */
    public function addServerCipherSuite(int $cipherSuite): self
    {
        if (!in_array($cipherSuite, $this->serverCipherSuites)) {
            $this->serverCipherSuites[] = $cipherSuite;
        }
        return $this;
    }
    
    /**
     * 从客户端的加密套件列表中选择最佳的加密套件
     * 
     * @param array<int> $clientCipherSuites 客户端支持的加密套件列表
     * @return int|null 选择的加密套件，如果没有匹配的则返回null
     */
    public function negotiate(array $clientCipherSuites): ?int
    {
        // 如果是TLS 1.3，需要过滤掉非TLS 1.3加密套件
        if ($this->version === TLSVersion::TLS_1_3) {
            $clientCipherSuites = array_filter($clientCipherSuites, function($cs) {
                return (new CipherSuite($cs))->isTLS13();
            });
            
            $serverCipherSuites = array_filter($this->serverCipherSuites, function($cs) {
                return (new CipherSuite($cs))->isTLS13();
            });
        } else {
            // 对于TLS 1.2及以下版本，过滤掉TLS 1.3加密套件
            $clientCipherSuites = array_filter($clientCipherSuites, function($cs) {
                return !(new CipherSuite($cs))->isTLS13();
            });
            
            $serverCipherSuites = array_filter($this->serverCipherSuites, function($cs) {
                return !(new CipherSuite($cs))->isTLS13();
            });
        }
        
        // 按照服务器的优先级顺序遍历服务器支持的加密套件
        foreach ($serverCipherSuites as $serverCipherSuite) {
            // 如果客户端也支持此加密套件，则选择它
            if (in_array($serverCipherSuite, $clientCipherSuites)) {
                return $serverCipherSuite;
            }
        }
        
        // 如果没有找到匹配的加密套件，则返回null
        return null;
    }
    
    /**
     * 检查加密套件是否安全（不含已知的弱密码学算法）
     * 
     * @param int $cipherSuite 加密套件
     * @return bool 是否安全
     */
    public static function isCipherSuiteSecure(int $cipherSuite): bool
    {
        // 检查已知不安全的加密套件
        $insecureCipherSuites = [
            CipherSuite::TLS_RSA_WITH_NULL_MD5,
            CipherSuite::TLS_RSA_WITH_NULL_SHA
        ];
        
        if (in_array($cipherSuite, $insecureCipherSuites)) {
            return false;
        }
        
        // 检查加密套件名称是否包含弱算法关键词
        $name = CipherSuite::getCipherSuiteName($cipherSuite);
        
        $weakAlgorithms = [
            '_NULL_', // 无加密
            '_RC4_',  // RC4流密码（已被证明不安全）
            '_DES_',  // DES加密（密钥长度太短）
            '_3DES_', // 3DES加密（虽然比DES安全，但已过时）
            '_MD5',   // MD5哈希（已被证明不安全）
        ];
        
        foreach ($weakAlgorithms as $weakAlgo) {
            if (strpos($name, $weakAlgo) !== false) {
                return false;
            }
        }
        
        return true;
    }
} 
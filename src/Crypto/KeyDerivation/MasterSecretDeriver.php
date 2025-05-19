<?php

declare(strict_types=1);

namespace Tourze\TLSHandshake\Crypto\KeyDerivation;

/**
 * 主密钥派生器
 * 实现TLS 1.2和TLS 1.3主密钥生成
 */
class MasterSecretDeriver
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
     * 从预主密钥派生TLS 1.2主密钥
     * 
     * @param string $premaster 预主密钥
     * @param string $clientRandom 客户端随机数
     * @param string $serverRandom 服务器随机数
     * @return string 主密钥
     */
    public function deriveTLS12(string $premaster, string $clientRandom, string $serverRandom): string
    {
        return $this->prf->generateMasterSecret($premaster, $clientRandom, $serverRandom);
    }
    
    /**
     * 从握手密钥派生TLS 1.3主密钥
     * 
     * @param string $handshakeSecret 握手密钥
     * @return string 主密钥
     */
    public function deriveTLS13(string $handshakeSecret): string
    {
        return $this->hkdf->deriveMasterSecret($handshakeSecret);
    }
    
    /**
     * 创建TLS 1.3早期密钥
     * 
     * @param string $psk 预共享密钥(如果有)
     * @return string 早期密钥
     */
    public function createTLS13EarlySecret(string $psk = ''): string
    {
        return $this->hkdf->deriveEarlySecret($psk);
    }
    
    /**
     * 从早期密钥和共享密钥派生TLS 1.3握手密钥
     * 
     * @param string $earlySecret 早期密钥
     * @param string $sharedSecret 共享密钥(通常是密钥交换的结果)
     * @return string 握手密钥
     */
    public function deriveHandshakeSecret(string $earlySecret, string $sharedSecret): string
    {
        return $this->hkdf->deriveHandshakeSecret($earlySecret, $sharedSecret);
    }
    
    /**
     * 从握手上下文派生TLS 1.3客户端握手流量密钥
     * 
     * @param string $handshakeSecret 握手密钥
     * @param string $handshakeContext 握手上下文(ClientHello到ServerHello)
     * @return string 客户端握手流量密钥
     */
    public function deriveClientHandshakeTrafficSecret(string $handshakeSecret, string $handshakeContext): string
    {
        return $this->hkdf->deriveSecret($handshakeSecret, 'c hs traffic', $handshakeContext);
    }
    
    /**
     * 从握手上下文派生TLS 1.3服务器握手流量密钥
     * 
     * @param string $handshakeSecret 握手密钥
     * @param string $handshakeContext 握手上下文(ClientHello到ServerHello)
     * @return string 服务器握手流量密钥
     */
    public function deriveServerHandshakeTrafficSecret(string $handshakeSecret, string $handshakeContext): string
    {
        return $this->hkdf->deriveSecret($handshakeSecret, 's hs traffic', $handshakeContext);
    }
    
    /**
     * 从主密钥派生TLS 1.3客户端应用流量密钥
     * 
     * @param string $masterSecret 主密钥
     * @param string $handshakeContext 完整握手上下文
     * @return string 客户端应用流量密钥
     */
    public function deriveClientApplicationTrafficSecret(string $masterSecret, string $handshakeContext): string
    {
        return $this->hkdf->deriveSecret($masterSecret, 'c ap traffic', $handshakeContext);
    }
    
    /**
     * 从主密钥派生TLS 1.3服务器应用流量密钥
     * 
     * @param string $masterSecret 主密钥
     * @param string $handshakeContext 完整握手上下文
     * @return string 服务器应用流量密钥
     */
    public function deriveServerApplicationTrafficSecret(string $masterSecret, string $handshakeContext): string
    {
        return $this->hkdf->deriveSecret($masterSecret, 's ap traffic', $handshakeContext);
    }
    
    /**
     * 从主密钥派生TLS 1.3导出主密钥
     * 
     * @param string $masterSecret 主密钥
     * @param string $handshakeContext 完整握手上下文
     * @return string 导出主密钥
     */
    public function deriveExporterMasterSecret(string $masterSecret, string $handshakeContext): string
    {
        return $this->hkdf->deriveSecret($masterSecret, 'exp master', $handshakeContext);
    }
    
    /**
     * 从主密钥派生TLS 1.3恢复主密钥
     * 
     * @param string $masterSecret 主密钥
     * @param string $handshakeContext 完整握手上下文
     * @return string 恢复主密钥
     */
    public function deriveResumptionMasterSecret(string $masterSecret, string $handshakeContext): string
    {
        return $this->hkdf->deriveSecret($masterSecret, 'res master', $handshakeContext);
    }
}

<?php

namespace Tourze\TLSHandshake\Crypto\Certificate;

use Tourze\TLSHandshake\Config\HandshakeConfig;
use Tourze\TLSHandshake\Message\CertificateRequestMessage;

/**
 * 客户端证书处理器
 */
class ClientCertificateHandler
{
    /**
     * 握手配置
     */
    private HandshakeConfig $config;
    
    /**
     * 证书类型：RSA签名
     */
    public const CERT_TYPE_RSA_SIGN = 1;
    
    /**
     * 证书类型：DSS签名
     */
    public const CERT_TYPE_DSS_SIGN = 2;
    
    /**
     * 证书类型：RSA固定DH
     */
    public const CERT_TYPE_RSA_FIXED_DH = 3;
    
    /**
     * 证书类型：DSS固定DH
     */
    public const CERT_TYPE_DSS_FIXED_DH = 4;
    
    /**
     * 证书类型：ECDSA签名
     */
    public const CERT_TYPE_ECDSA_SIGN = 64;
    
    /**
     * 构造函数
     *
     * @param HandshakeConfig $config 握手配置
     */
    public function __construct(HandshakeConfig $config)
    {
        $this->config = $config;
    }
    
    /**
     * 处理证书请求消息
     *
     * @param CertificateRequestMessage $requestMessage 证书请求消息
     * @return array{certificate: string, privateKey: string}|null 选择的证书和私钥，如果没有匹配的证书返回null
     */
    public function handleCertificateRequest(CertificateRequestMessage $requestMessage): ?array
    {
        $certPath = $this->config->getClientCertificatePath();
        $keyPath = $this->config->getClientPrivateKeyPath();
        
        // 检查是否配置了客户端证书
        if (!$certPath || !$keyPath || !file_exists($certPath) || !file_exists($keyPath)) {
            return null;
        }
        
        try {
            $certData = $this->loadCertificateData($certPath, $keyPath);
            $certificateType = $this->getCertificateType($certData['certificate']);
            
            // 检查服务器是否接受此类型的证书
            $acceptedTypes = $requestMessage->getCertificateTypes();
            if (!in_array($certificateType, $acceptedTypes, true)) {
                return null;
            }
            
            // 检查证书CA是否被服务器接受
            $certificateAuthorities = $requestMessage->getCertificateAuthorities();
            if (!empty($certificateAuthorities) && !$this->isIssuedByAcceptedCA($certData['certificate'], $certificateAuthorities)) {
                return null;
            }
            
            return $certData;
        } catch (\Exception $e) {
            // 如果加载证书失败，返回null
            return null;
        }
    }
    
    /**
     * 加载证书和私钥数据
     *
     * @param string $certPath 证书路径
     * @param string $keyPath 私钥路径
     * @return array{certificate: string, privateKey: string} 证书及私钥数据
     * @throws \RuntimeException 如果加载失败
     */
    protected function loadCertificateData(string $certPath, string $keyPath): array
    {
        $certificate = file_get_contents($certPath);
        $privateKey = file_get_contents($keyPath);
        
        if ($certificate === false || $privateKey === false) {
            throw new \RuntimeException('无法读取证书或私钥文件');
        }
        
        // 验证证书和私钥格式
        if (!openssl_x509_read($certificate)) {
            throw new \RuntimeException('无效的证书格式');
        }
        
        if (!openssl_pkey_get_private($privateKey)) {
            throw new \RuntimeException('无效的私钥格式');
        }
        
        return [
            'certificate' => $certificate,
            'privateKey' => $privateKey
        ];
    }
    
    /**
     * 获取证书类型
     *
     * @param string $certificate 证书数据
     * @return int 证书类型
     */
    protected function getCertificateType(string $certificate): int
    {
        $certResource = openssl_x509_read($certificate);
        if (!$certResource) {
            return self::CERT_TYPE_RSA_SIGN; // 默认返回RSA
        }
        
        $publicKey = openssl_get_publickey($certResource);
        if (!$publicKey) {
            return self::CERT_TYPE_RSA_SIGN;
        }
        
        $keyDetails = openssl_pkey_get_details($publicKey);
        
        if (!isset($keyDetails['type'])) {
            return self::CERT_TYPE_RSA_SIGN;
        }
        
        return match ($keyDetails['type']) {
            OPENSSL_KEYTYPE_RSA => self::CERT_TYPE_RSA_SIGN,
            OPENSSL_KEYTYPE_DSA => self::CERT_TYPE_DSS_SIGN,
            OPENSSL_KEYTYPE_EC => self::CERT_TYPE_ECDSA_SIGN,
            default => self::CERT_TYPE_RSA_SIGN
        };
    }
    
    /**
     * 检查证书是否由服务器接受的CA颁发
     *
     * @param string $certificate 证书数据
     * @param array<string> $acceptedCAs 服务器接受的CA列表
     * @return bool 是否被接受
     */
    protected function isIssuedByAcceptedCA(string $certificate, array $acceptedCAs): bool
    {
        if (empty($acceptedCAs)) {
            return true; // 如果服务器没有指定CA，则接受所有证书
        }
        
        $certInfo = openssl_x509_parse($certificate);
        if (!$certInfo || !isset($certInfo['issuer'])) {
            return false;
        }
        
        // 构建证书颁发者的DN字符串
        $issuerDN = $this->buildDN($certInfo['issuer']);
        
        // 检查颁发者是否在接受的CA列表中
        foreach ($acceptedCAs as $acceptedCA) {
            if (strpos($issuerDN, $acceptedCA) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 构建可辨别名称(DN)字符串
     *
     * @param array<string, string> $dn 名称组件
     * @return string DN字符串
     */
    private function buildDN(array $dn): string
    {
        $parts = [];
        
        // 按照X.500标准顺序构建DN
        $keys = [
            'CN' => 'commonName',
            'OU' => 'organizationalUnitName',
            'O' => 'organizationName',
            'L' => 'localityName',
            'ST' => 'stateOrProvinceName',
            'C' => 'countryName'
        ];
        
        foreach ($keys as $key => $longName) {
            if (isset($dn[$key])) {
                $parts[] = "$key={$dn[$key]}";
            } elseif (isset($dn[$longName])) {
                $parts[] = "$key={$dn[$longName]}";
            }
        }
        
        return implode(', ', $parts);
    }
} 
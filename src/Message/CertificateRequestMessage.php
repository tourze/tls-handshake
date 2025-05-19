<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS CertificateRequest消息
 * 
 * 参考RFC 5246 (TLS 1.2) 和 RFC 8446 (TLS 1.3)
 */
class CertificateRequestMessage extends AbstractHandshakeMessage
{
    /**
     * 支持的证书类型列表
     * 
     * @var array<int>
     */
    private array $certificateTypes = [];
    
    /**
     * 支持的签名算法列表
     * 
     * @var array<int>
     */
    private array $signatureAlgorithms = [];
    
    /**
     * 可接受的证书颁发机构名称列表
     * 
     * @var array<string>
     */
    private array $certificateAuthorities = [];
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = HandshakeMessageType::CERTIFICATE_REQUEST;
    }
    
    /**
     * 获取支持的证书类型列表
     * 
     * @return array<int> 证书类型列表
     */
    public function getCertificateTypes(): array
    {
        return $this->certificateTypes;
    }
    
    /**
     * 设置支持的证书类型列表
     * 
     * @param array<int> $certificateTypes 证书类型列表
     * @return self
     */
    public function setCertificateTypes(array $certificateTypes): self
    {
        $this->certificateTypes = $certificateTypes;
        return $this;
    }
    
    /**
     * 添加支持的证书类型
     * 
     * @param int $certificateType 证书类型
     * @return self
     */
    public function addCertificateType(int $certificateType): self
    {
        $this->certificateTypes[] = $certificateType;
        return $this;
    }
    
    /**
     * 获取支持的签名算法列表
     * 
     * @return array<int> 签名算法列表
     */
    public function getSignatureAlgorithms(): array
    {
        return $this->signatureAlgorithms;
    }
    
    /**
     * 设置支持的签名算法列表
     * 
     * @param array<int> $signatureAlgorithms 签名算法列表
     * @return self
     */
    public function setSignatureAlgorithms(array $signatureAlgorithms): self
    {
        $this->signatureAlgorithms = $signatureAlgorithms;
        return $this;
    }
    
    /**
     * 添加支持的签名算法
     * 
     * @param int $signatureAlgorithm 签名算法
     * @return self
     */
    public function addSignatureAlgorithm(int $signatureAlgorithm): self
    {
        $this->signatureAlgorithms[] = $signatureAlgorithm;
        return $this;
    }
    
    /**
     * 获取可接受的证书颁发机构列表
     * 
     * @return array<string> 证书颁发机构列表
     */
    public function getCertificateAuthorities(): array
    {
        return $this->certificateAuthorities;
    }
    
    /**
     * 设置可接受的证书颁发机构列表
     * 
     * @param array<string> $certificateAuthorities 证书颁发机构列表
     * @return self
     */
    public function setCertificateAuthorities(array $certificateAuthorities): self
    {
        $this->certificateAuthorities = $certificateAuthorities;
        return $this;
    }
    
    /**
     * 添加可接受的证书颁发机构
     * 
     * @param string $certificateAuthority 证书颁发机构
     * @return self
     */
    public function addCertificateAuthority(string $certificateAuthority): self
    {
        $this->certificateAuthorities[] = $certificateAuthority;
        return $this;
    }
    
    /**
     * 将消息序列化为二进制数据
     * 
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        // CertificateTypes
        $result = $this->encodeUint8(count($this->certificateTypes));
        foreach ($this->certificateTypes as $type) {
            $result .= $this->encodeUint8($type);
        }
        
        // SignatureAlgorithms
        if (!empty($this->signatureAlgorithms)) {
            $signatureAlgorithmsData = '';
            foreach ($this->signatureAlgorithms as $algorithm) {
                $signatureAlgorithmsData .= $this->encodeUint16($algorithm);
            }
            
            $result .= $this->encodeUint16(strlen($signatureAlgorithmsData));
            $result .= $signatureAlgorithmsData;
        } else {
            $result .= $this->encodeUint16(0); // 空的签名算法列表
        }
        
        // CertificateAuthorities
        $certificateAuthoritiesData = '';
        foreach ($this->certificateAuthorities as $authority) {
            $authorityData = $authority;
            $certificateAuthoritiesData .= $this->encodeUint16(strlen($authorityData));
            $certificateAuthoritiesData .= $authorityData;
        }
        
        $result .= $this->encodeUint16(strlen($certificateAuthoritiesData));
        $result .= $certificateAuthoritiesData;
        
        return $result;
    }
    
    /**
     * 从二进制数据反序列化消息
     * 
     * @param string $data 二进制数据
     * @return static 解析后的消息对象
     * @throws \InvalidArgumentException 如果数据格式无效
     */
    public static function decode(string $data): static
    {
        $message = new static();
        $offset = 0;
        
        // 检查数据长度
        if (strlen($data) < 5) { // 最小长度: 证书类型长度(1) + 签名算法长度(2) + CA列表长度(2)
            throw new \InvalidArgumentException('CertificateRequest message too short');
        }
        
        // CertificateTypes
        $certificateTypesCount = self::decodeUint8($data, $offset);
        $offset += 1;
        
        // 检查数据长度是否足够
        if ($offset + $certificateTypesCount > strlen($data)) {
            throw new \InvalidArgumentException('CertificateRequest message certificate types length mismatch');
        }
        
        for ($i = 0; $i < $certificateTypesCount; $i++) {
            $message->addCertificateType(self::decodeUint8($data, $offset));
            $offset += 1;
        }
        
        // SignatureAlgorithms
        $signatureAlgorithmsLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 检查数据长度是否足够
        if ($offset + $signatureAlgorithmsLength > strlen($data)) {
            throw new \InvalidArgumentException('CertificateRequest message signature algorithms length mismatch');
        }
        
        $signatureAlgorithmsEnd = $offset + $signatureAlgorithmsLength;
        while ($offset < $signatureAlgorithmsEnd) {
            $message->addSignatureAlgorithm(self::decodeUint16($data, $offset));
            $offset += 2;
        }
        
        // CertificateAuthorities
        $certificateAuthoritiesLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 检查数据长度是否足够
        if ($offset + $certificateAuthoritiesLength > strlen($data)) {
            throw new \InvalidArgumentException('CertificateRequest message certificate authorities length mismatch');
        }
        
        $certificateAuthoritiesEnd = $offset + $certificateAuthoritiesLength;
        while ($offset < $certificateAuthoritiesEnd) {
            $authorityLength = self::decodeUint16($data, $offset);
            $offset += 2;
            
            // 检查是否有足够的数据
            if ($offset + $authorityLength > $certificateAuthoritiesEnd) {
                throw new \InvalidArgumentException('CertificateRequest message certificate authority length exceeds message bounds');
            }
            
            $authority = substr($data, $offset, $authorityLength);
            $offset += $authorityLength;
            
            $message->addCertificateAuthority($authority);
        }
        
        return $message;
    }
    
    /**
     * 验证消息是否有效
     * 
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        // 必须有至少一个证书类型
        return !empty($this->certificateTypes);
    }
}

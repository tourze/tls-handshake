<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS Certificate消息
 * 
 * 参考RFC 5246 (TLS 1.2) 和 RFC 8446 (TLS 1.3)
 */
class CertificateMessage extends AbstractHandshakeMessage
{
    /**
     * 证书链
     * 
     * @var array<string>
     */
    private array $certificates = [];
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = HandshakeMessageType::CERTIFICATE;
    }
    
    /**
     * 获取证书链
     * 
     * @return array<string> 证书链
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }
    
    /**
     * 设置证书链
     * 
     * @param array<string> $certificates 证书链
     * @return self
     */
    public function setCertificates(array $certificates): self
    {
        $this->certificates = $certificates;
        return $this;
    }
    
    /**
     * 添加证书
     * 
     * @param string $certificate 证书数据
     * @return self
     */
    public function addCertificate(string $certificate): self
    {
        $this->certificates[] = $certificate;
        return $this;
    }
    
    /**
     * 将消息序列化为二进制数据
     * 
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        $certificatesData = '';
        
        // 编码每个证书
        foreach ($this->certificates as $certificate) {
            // 每个证书前面有3字节的长度
            $certificatesData .= $this->encodeUint24(strlen($certificate));
            $certificatesData .= $certificate;
        }
        
        // 证书链总长度（3字节）
        $result = $this->encodeUint24(strlen($certificatesData));
        $result .= $certificatesData;
        
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
        if (strlen($data) < 3) { // 至少需要3字节的证书链长度
            throw new \InvalidArgumentException('Certificate message too short');
        }
        
        // 证书链总长度
        $certificatesLength = self::decodeUint24($data, $offset);
        $offset += 3;
        
        // 检查数据长度是否一致
        if ($offset + $certificatesLength > strlen($data)) {
            throw new \InvalidArgumentException('Certificate message length mismatch');
        }
        
        // 解析证书链
        $certificatesEnd = $offset + $certificatesLength;
        while ($offset < $certificatesEnd) {
            // 证书长度（3字节）
            if ($offset + 3 > $certificatesEnd) {
                throw new \InvalidArgumentException('Incomplete certificate length field');
            }
            
            $certificateLength = self::decodeUint24($data, $offset);
            $offset += 3;
            
            // 检查是否有足够的数据
            if ($offset + $certificateLength > $certificatesEnd) {
                throw new \InvalidArgumentException('Certificate length exceeds message bounds');
            }
            
            // 获取证书数据
            $certificate = substr($data, $offset, $certificateLength);
            $offset += $certificateLength;
            
            $message->addCertificate($certificate);
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
        // 证书链不能为空
        return !empty($this->certificates);
    }
    
    /**
     * 编码一个无符号24位整数（big-endian）
     *
     * @param int $value 要编码的值
     * @return string 编码后的二进制数据
     */
    protected function encodeUint24(int $value): string
    {
        return chr(($value >> 16) & 0xFF) . chr(($value >> 8) & 0xFF) . chr($value & 0xFF);
    }
    
    /**
     * 解码一个无符号24位整数（big-endian）
     *
     * @param string $data 二进制数据
     * @param int $offset 起始偏移量
     * @return int 解码后的值
     * @throws \InvalidArgumentException 如果数据长度不足
     */
    protected static function decodeUint24(string $data, int $offset = 0): int
    {
        if (strlen($data) < $offset + 3) {
            throw new \InvalidArgumentException('Data too short for Uint24');
        }
        
        return (ord($data[$offset]) << 16) | (ord($data[$offset + 1]) << 8) | ord($data[$offset + 2]);
    }
}

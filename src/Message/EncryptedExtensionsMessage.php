<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS EncryptedExtensions消息
 * 
 * 参考RFC 8446 (TLS 1.3) - 仅在TLS 1.3中使用
 * EncryptedExtensions消息包含了服务器响应的非加密相关的扩展，这些扩展在TLS 1.3中是被加密传输的。
 */
class EncryptedExtensionsMessage extends AbstractHandshakeMessage
{
    /**
     * 扩展列表
     * 
     * @var array<int, string>
     */
    private array $extensions = [];
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = HandshakeMessageType::ENCRYPTED_EXTENSIONS;
    }
    
    /**
     * 获取扩展列表
     * 
     * @return array<int, string> 扩展列表
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }
    
    /**
     * 设置扩展列表
     * 
     * @param array<int, string> $extensions 扩展列表
     * @return self
     */
    public function setExtensions(array $extensions): self
    {
        $this->extensions = $extensions;
        return $this;
    }
    
    /**
     * 添加扩展
     * 
     * @param int $type 扩展类型
     * @param string $data 扩展数据
     * @return self
     */
    public function addExtension(int $type, string $data): self
    {
        $this->extensions[$type] = $data;
        return $this;
    }
    
    /**
     * 将消息序列化为二进制数据
     * 
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        // 先组装扩展列表数据
        $extensionsData = '';
        foreach ($this->extensions as $type => $data) {
            // 扩展类型
            $extensionsData .= $this->encodeUint16($type);
            // 扩展数据长度
            $extensionsData .= $this->encodeUint16(strlen($data));
            // 扩展数据
            $extensionsData .= $data;
        }
        
        // 扩展列表总长度
        $result = $this->encodeUint16(strlen($extensionsData));
        // 扩展列表数据
        $result .= $extensionsData;
        
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
        if (strlen($data) < 2) { // 至少需要2字节的扩展列表长度
            throw new \InvalidArgumentException('EncryptedExtensions message too short');
        }
        
        // 扩展列表长度
        $extensionsLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 检查数据长度是否足够
        if ($offset + $extensionsLength > strlen($data)) {
            throw new \InvalidArgumentException('EncryptedExtensions message extensions length mismatch');
        }
        
        // 解析扩展列表
        $extensionsEnd = $offset + $extensionsLength;
        while ($offset < $extensionsEnd) {
            // 确保有足够的数据来解析扩展类型和长度
            if ($offset + 4 > $extensionsEnd) {
                throw new \InvalidArgumentException('EncryptedExtensions message extension header incomplete');
            }
            
            // 扩展类型
            $extensionType = self::decodeUint16($data, $offset);
            $offset += 2;
            
            // 扩展数据长度
            $extensionLength = self::decodeUint16($data, $offset);
            $offset += 2;
            
            // 检查是否有足够的数据
            if ($offset + $extensionLength > $extensionsEnd) {
                throw new \InvalidArgumentException('EncryptedExtensions message extension data incomplete');
            }
            
            // 扩展数据
            $extensionData = substr($data, $offset, $extensionLength);
            $offset += $extensionLength;
            
            // 添加扩展
            $message->addExtension($extensionType, $extensionData);
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
        // EncryptedExtensions消息即使没有扩展也是有效的
        return true;
    }
} 
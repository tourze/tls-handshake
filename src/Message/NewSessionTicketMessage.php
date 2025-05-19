<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS NewSessionTicket消息
 * 
 * 参考RFC 8446 (TLS 1.3) - 在TLS 1.3中用于会话恢复
 * NewSessionTicket消息由服务器发送给客户端，提供会话恢复所需的状态信息。
 */
class NewSessionTicketMessage extends AbstractHandshakeMessage
{
    /**
     * 票据生命周期（以秒为单位）
     * 
     * @var int
     */
    private int $ticketLifetime = 0;
    
    /**
     * 票据年龄附加值
     * 
     * @var int
     */
    private int $ticketAgeAdd = 0;
    
    /**
     * 票据随机数
     * 
     * @var string
     */
    private string $ticketNonce = '';
    
    /**
     * 票据数据
     * 
     * @var string
     */
    private string $ticket = '';
    
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
        $this->type = HandshakeMessageType::NEW_SESSION_TICKET;
    }
    
    /**
     * 获取票据生命周期
     * 
     * @return int 票据生命周期（以秒为单位）
     */
    public function getTicketLifetime(): int
    {
        return $this->ticketLifetime;
    }
    
    /**
     * 设置票据生命周期
     * 
     * @param int $ticketLifetime 票据生命周期（以秒为单位）
     * @return self
     */
    public function setTicketLifetime(int $ticketLifetime): self
    {
        $this->ticketLifetime = $ticketLifetime;
        return $this;
    }
    
    /**
     * 获取票据年龄附加值
     * 
     * @return int 票据年龄附加值
     */
    public function getTicketAgeAdd(): int
    {
        return $this->ticketAgeAdd;
    }
    
    /**
     * 设置票据年龄附加值
     * 
     * @param int $ticketAgeAdd 票据年龄附加值
     * @return self
     */
    public function setTicketAgeAdd(int $ticketAgeAdd): self
    {
        $this->ticketAgeAdd = $ticketAgeAdd;
        return $this;
    }
    
    /**
     * 获取票据随机数
     * 
     * @return string 票据随机数
     */
    public function getTicketNonce(): string
    {
        return $this->ticketNonce;
    }
    
    /**
     * 设置票据随机数
     * 
     * @param string $ticketNonce 票据随机数
     * @return self
     */
    public function setTicketNonce(string $ticketNonce): self
    {
        $this->ticketNonce = $ticketNonce;
        return $this;
    }
    
    /**
     * 获取票据数据
     * 
     * @return string 票据数据
     */
    public function getTicket(): string
    {
        return $this->ticket;
    }
    
    /**
     * 设置票据数据
     * 
     * @param string $ticket 票据数据
     * @return self
     */
    public function setTicket(string $ticket): self
    {
        $this->ticket = $ticket;
        return $this;
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
        // 票据生命周期 (4字节)
        $result = $this->encodeUint32($this->ticketLifetime);
        
        // 票据年龄附加值 (4字节)
        $result .= $this->encodeUint32($this->ticketAgeAdd);
        
        // 票据随机数长度 (1字节) 和数据
        $result .= $this->encodeUint8(strlen($this->ticketNonce));
        $result .= $this->ticketNonce;
        
        // 票据长度 (2字节) 和数据
        $result .= $this->encodeUint16(strlen($this->ticket));
        $result .= $this->ticket;
        
        // 扩展列表
        $extensionsData = '';
        foreach ($this->extensions as $type => $data) {
            // 扩展类型
            $extensionsData .= $this->encodeUint16($type);
            // 扩展数据长度
            $extensionsData .= $this->encodeUint16(strlen($data));
            // 扩展数据
            $extensionsData .= $data;
        }
        
        // 扩展列表总长度 (2字节) 和数据
        $result .= $this->encodeUint16(strlen($extensionsData));
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
        if (strlen($data) < 11) { // 最小长度: 生命周期(4) + 年龄附加值(4) + 随机数长度(1) + 票据长度(2)
            throw new \InvalidArgumentException('NewSessionTicket message too short');
        }
        
        // 票据生命周期
        $message->setTicketLifetime(self::decodeUint32($data, $offset));
        $offset += 4;
        
        // 票据年龄附加值
        $message->setTicketAgeAdd(self::decodeUint32($data, $offset));
        $offset += 4;
        
        // 票据随机数长度
        $nonceLength = self::decodeUint8($data, $offset);
        $offset += 1;
        
        // 检查随机数长度是否合理
        if ($offset + $nonceLength > strlen($data)) {
            throw new \InvalidArgumentException('NewSessionTicket message nonce length mismatch');
        }
        
        // 票据随机数
        $message->setTicketNonce(substr($data, $offset, $nonceLength));
        $offset += $nonceLength;
        
        // 检查剩余数据是否足够
        if ($offset + 2 > strlen($data)) {
            throw new \InvalidArgumentException('NewSessionTicket message ticket length field missing');
        }
        
        // 票据长度
        $ticketLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 检查票据长度是否合理
        if ($offset + $ticketLength > strlen($data)) {
            throw new \InvalidArgumentException('NewSessionTicket message ticket length mismatch');
        }
        
        // 票据数据
        $message->setTicket(substr($data, $offset, $ticketLength));
        $offset += $ticketLength;
        
        // 检查剩余数据是否足够
        if ($offset + 2 > strlen($data)) {
            throw new \InvalidArgumentException('NewSessionTicket message extensions length field missing');
        }
        
        // 扩展列表长度
        $extensionsLength = self::decodeUint16($data, $offset);
        $offset += 2;
        
        // 检查扩展列表长度是否合理
        if ($offset + $extensionsLength > strlen($data)) {
            throw new \InvalidArgumentException('NewSessionTicket message extensions length mismatch');
        }
        
        // 解析扩展列表
        $extensionsEnd = $offset + $extensionsLength;
        while ($offset < $extensionsEnd) {
            // 确保有足够的数据来解析扩展类型和长度
            if ($offset + 4 > $extensionsEnd) {
                throw new \InvalidArgumentException('NewSessionTicket message extension header incomplete');
            }
            
            // 扩展类型
            $extensionType = self::decodeUint16($data, $offset);
            $offset += 2;
            
            // 扩展数据长度
            $extensionLength = self::decodeUint16($data, $offset);
            $offset += 2;
            
            // 检查是否有足够的数据
            if ($offset + $extensionLength > $extensionsEnd) {
                throw new \InvalidArgumentException('NewSessionTicket message extension data incomplete');
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
        // 必须有票据数据
        return !empty($this->ticket);
    }
} 
<?php

namespace Tourze\TLSHandshake\Message;

use Tourze\TLSHandshake\Protocol\HandshakeMessageType;

/**
 * TLS握手消息抽象类
 */
abstract class AbstractHandshakeMessage implements HandshakeMessageInterface
{
    /**
     * 消息类型
     *
     * @var HandshakeMessageType
     */
    protected HandshakeMessageType $type;
    
    /**
     * 原始消息数据
     *
     * @var string|null
     */
    protected ?string $rawData = null;
    
    /**
     * 获取消息类型
     *
     * @return HandshakeMessageType 消息类型
     */
    public function getType(): HandshakeMessageType
    {
        return $this->type;
    }
    
    /**
     * 获取消息长度
     *
     * @return int 消息长度（字节数）
     */
    public function getLength(): int
    {
        return strlen($this->encode());
    }
    
    /**
     * 验证消息是否有效
     *
     * @return bool 是否有效
     */
    public function isValid(): bool
    {
        return true;
    }
    
    /**
     * 编码一个无符号16位整数（big-endian）
     *
     * @param int $value 要编码的值
     * @return string 编码后的二进制数据
     */
    protected function encodeUint16(int $value): string
    {
        return pack('n', $value);
    }
    
    /**
     * 编码一个无符号32位整数（big-endian）
     *
     * @param int $value 要编码的值
     * @return string 编码后的二进制数据
     */
    protected function encodeUint32(int $value): string
    {
        return pack('N', $value);
    }
    
    /**
     * 编码一个无符号8位整数
     *
     * @param int $value 要编码的值
     * @return string 编码后的二进制数据
     */
    protected function encodeUint8(int $value): string
    {
        return pack('C', $value);
    }
    
    /**
     * 解码一个无符号16位整数（big-endian）
     *
     * @param string $data 二进制数据
     * @param int $offset 起始偏移量
     * @return int 解码后的值
     */
    protected static function decodeUint16(string $data, int $offset = 0): int
    {
        $value = unpack('n', substr($data, $offset, 2));
        return $value[1];
    }
    
    /**
     * 解码一个无符号32位整数（big-endian）
     *
     * @param string $data 二进制数据
     * @param int $offset 起始偏移量
     * @return int 解码后的值
     */
    protected static function decodeUint32(string $data, int $offset = 0): int
    {
        $value = unpack('N', substr($data, $offset, 4));
        return $value[1];
    }
    
    /**
     * 解码一个无符号8位整数
     *
     * @param string $data 二进制数据
     * @param int $offset 起始偏移量
     * @return int 解码后的值
     */
    protected static function decodeUint8(string $data, int $offset = 0): int
    {
        $value = unpack('C', substr($data, $offset, 1));
        return $value[1];
    }
}

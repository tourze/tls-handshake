<?php

namespace Tourze\TLSHandshake\Extension;

/**
 * TLS扩展抽象基类
 * 
 * 提供所有TLS扩展的基本功能
 */
abstract class AbstractExtension implements ExtensionInterface
{
    /**
     * 编码16位无符号整数
     * 
     * @param int $value 整数值
     * @return string 二进制表示
     */
    protected function encodeUint16(int $value): string
    {
        return pack('n', $value);
    }
    
    /**
     * 解码16位无符号整数
     * 
     * @param string $data 二进制数据
     * @param int $offset 起始偏移量
     * @return int 解码后的整数值
     */
    protected static function decodeUint16(string $data, int &$offset): int
    {
        $value = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        return $value;
    }
    
    /**
     * 判断扩展是否适用于指定TLS版本
     * 
     * 默认实现为所有版本都适用，子类可以覆盖此方法以限制版本范围
     * 
     * @param string $tlsVersion TLS版本
     * @return bool 是否适用
     */
    public function isApplicableForVersion(string $tlsVersion): bool
    {
        return true;
    }
}

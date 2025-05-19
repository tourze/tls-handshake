<?php

namespace Tourze\TLSHandshake\Crypto\KeyExchange;

/**
 * 密钥交换接口
 * 
 * 定义所有密钥交换算法必须实现的方法
 */
interface KeyExchangeInterface
{
    /**
     * 获取预主密钥
     * 
     * @return string 预主密钥
     */
    public function getPreMasterSecret(): string;
} 
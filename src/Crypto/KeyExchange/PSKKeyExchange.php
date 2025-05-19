<?php

namespace Tourze\TLSHandshake\Crypto\KeyExchange;

/**
 * PSK密钥交换实现
 * 
 * 参考RFC 4279 - TLS 1.2中的PSK密钥交换
 */
class PSKKeyExchange implements KeyExchangeInterface
{
    /**
     * PSK身份
     * 
     * @var string
     */
    private string $identity = '';
    
    /**
     * 预共享密钥
     * 
     * @var string
     */
    private string $psk = '';
    
    /**
     * 预主密钥
     * 
     * @var string
     */
    private string $preMasterSecret = '';
    
    /**
     * 设置PSK身份和密钥
     * 
     * @param string $identity PSK身份
     * @param string $psk 预共享密钥
     * @return self
     */
    public function setPSK(string $identity, string $psk): self
    {
        $this->identity = $identity;
        $this->psk = $psk;
        return $this;
    }
    
    /**
     * 获取PSK身份
     * 
     * @return string PSK身份
     */
    public function getIdentity(): string
    {
        return $this->identity;
    }
    
    /**
     * 生成预主密钥
     * 
     * PSK预主密钥格式：
     * 纯PSK: 0x00 + PSK长度（两个字节）+ 0x00 + PSK
     * 
     * @return string 生成的预主密钥
     * @throws \RuntimeException 如果PSK未设置
     */
    public function generatePreMasterSecret(): string
    {
        if (empty($this->psk)) {
            throw new \RuntimeException('PSK not set');
        }
        
        // 生成预主密钥格式：
        // 对于纯PSK（RFC 4279）：
        // PMS = zeros(其他密钥交换算法的长度) + PSK
        
        // 使用标准的格式：长度为0的"其他密钥"+ PSK
        $otherSecretLength = pack('n', 0); // 两个字节的0
        $pskLength = pack('n', strlen($this->psk));
        
        $this->preMasterSecret = $otherSecretLength . str_repeat("\0", 0) . $pskLength . $this->psk;
        
        return $this->preMasterSecret;
    }
    
    /**
     * 获取预主密钥
     * 
     * @return string 预主密钥
     */
    public function getPreMasterSecret(): string
    {
        return $this->preMasterSecret;
    }
    
    /**
     * 格式化PSK身份为二进制格式
     * 
     * 用于在ClientKeyExchange消息中发送
     * 
     * @return string 格式化的PSK身份
     * @throws \RuntimeException 如果身份未设置
     */
    public function formatIdentity(): string
    {
        if (empty($this->identity)) {
            throw new \RuntimeException('PSK identity not set');
        }
        
        // PSK身份长度（2字节）+ PSK身份
        $identityLength = pack('n', strlen($this->identity));
        return $identityLength . $this->identity;
    }
} 
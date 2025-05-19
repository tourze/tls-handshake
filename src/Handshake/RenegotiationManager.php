<?php

namespace Tourze\TLSHandshake\Handshake;

use Tourze\TLSHandshake\Extension\RenegotiationInfoExtension;
use Tourze\TLSHandshake\Protocol\TLSVersion;

/**
 * TLS重协商管理器
 * 
 * 管理TLS连接的重协商过程，包括：
 * 1. 支持安全重协商（RFC 5746）
 * 2. 防御重协商DoS攻击
 * 3. 处理TLS 1.3后握手认证
 */
class RenegotiationManager
{
    /**
     * 是否支持安全重协商
     */
    private bool $secureRenegotiation = false;
    
    /**
     * 是否正在进行重协商
     */
    private bool $isRenegotiating = false;
    
    /**
     * 客户端验证数据（上一次握手的Finished消息）
     */
    private string $clientVerifyData = '';
    
    /**
     * 服务器验证数据（上一次握手的Finished消息）
     */
    private string $serverVerifyData = '';
    
    /**
     * 重协商次数
     */
    private int $renegotiationCount = 0;
    
    /**
     * 重协商次数限制（防御DoS攻击）
     */
    private int $renegotiationLimit = 3;
    
    /**
     * 检查是否支持指定TLS版本的重协商
     * 
     * @param TLSVersion $version TLS版本
     * @return bool 是否支持
     */
    public function isSupportedForVersion(TLSVersion $version): bool
    {
        // TLS 1.3 不支持重协商，使用后握手认证代替
        return $version !== TLSVersion::TLS_1_3;
    }
    
    /**
     * 设置是否启用安全重协商
     * 
     * @param bool $enabled 是否启用
     * @return self
     */
    public function setSecureRenegotiation(bool $enabled): self
    {
        $this->secureRenegotiation = $enabled;
        return $this;
    }
    
    /**
     * 检查是否启用了安全重协商
     * 
     * @return bool 是否启用
     */
    public function isSecureRenegotiation(): bool
    {
        return $this->secureRenegotiation;
    }
    
    /**
     * 开始重协商过程
     * 
     * @return self
     */
    public function startRenegotiation(): self
    {
        $this->isRenegotiating = true;
        return $this;
    }
    
    /**
     * 结束重协商过程
     * 
     * @return self
     */
    public function endRenegotiation(): self
    {
        $this->isRenegotiating = false;
        return $this;
    }
    
    /**
     * 检查是否正在进行重协商
     * 
     * @return bool 是否正在重协商
     */
    public function isRenegotiating(): bool
    {
        return $this->isRenegotiating;
    }
    
    /**
     * 存储客户端验证数据（Finished消息）
     * 
     * @param string $data 验证数据
     * @return self
     */
    public function storeClientVerifyData(string $data): self
    {
        $this->clientVerifyData = $data;
        return $this;
    }
    
    /**
     * 存储服务器验证数据（Finished消息）
     * 
     * @param string $data 验证数据
     * @return self
     */
    public function storeServerVerifyData(string $data): self
    {
        $this->serverVerifyData = $data;
        return $this;
    }
    
    /**
     * 获取客户端验证数据
     * 
     * @return string 验证数据
     */
    public function getClientVerifyData(): string
    {
        return $this->clientVerifyData;
    }
    
    /**
     * 获取服务器验证数据
     * 
     * @return string 验证数据
     */
    public function getServerVerifyData(): string
    {
        return $this->serverVerifyData;
    }
    
    /**
     * 设置重协商次数限制
     * 
     * @param int $limit 限制次数
     * @return self
     */
    public function setRenegotiationLimit(int $limit): self
    {
        $this->renegotiationLimit = $limit;
        return $this;
    }
    
    /**
     * 增加重协商计数
     * 
     * @return self
     */
    public function incrementRenegotiationCount(): self
    {
        $this->renegotiationCount++;
        return $this;
    }
    
    /**
     * 检查是否可以进行重协商（防止DoS攻击）
     * 
     * @return bool 是否可以重协商
     */
    public function canRenegotiate(): bool
    {
        return $this->renegotiationCount < $this->renegotiationLimit;
    }
    
    /**
     * 创建安全重协商信息扩展（用于ClientHello/ServerHello）
     * 
     * @return RenegotiationInfoExtension 安全重协商扩展
     */
    public function createRenegotiationInfoExtension(): RenegotiationInfoExtension
    {
        $extension = new RenegotiationInfoExtension();
        return $extension;
    }
    
    /**
     * 创建服务器端安全重协商扩展
     * 
     * @return RenegotiationInfoExtension 服务器端安全重协商扩展
     */
    public function createServerRenegotiationInfoExtension(): RenegotiationInfoExtension
    {
        $extension = new RenegotiationInfoExtension();
        
        // 如果是重协商，添加客户端和服务器的验证数据
        if ($this->isRenegotiating && $this->secureRenegotiation) {
            $extension->setRenegotiatedConnection($this->clientVerifyData . $this->serverVerifyData);
        }
        
        return $extension;
    }
    
    /**
     * 处理客户端的安全重协商扩展
     * 
     * @param RenegotiationInfoExtension $extension 客户端提供的扩展
     * @return bool 验证是否成功
     */
    public function processClientRenegotiationExtension(RenegotiationInfoExtension $extension): bool
    {
        // 如果未启用安全重协商，直接返回失败
        if (!$this->secureRenegotiation) {
            return false;
        }
        
        // 初始握手，客户端应该提供空的重协商数据
        if (!$this->isRenegotiating) {
            return $extension->getRenegotiatedConnection() === '';
        }
        
        // 重协商时，客户端应该提供上一次握手的验证数据
        return $extension->getRenegotiatedConnection() === $this->clientVerifyData;
    }
    
    /**
     * 处理服务器端的安全重协商扩展
     * 
     * @param RenegotiationInfoExtension $extension 服务器提供的扩展
     * @return bool 验证是否成功
     */
    public function processServerRenegotiationExtension(RenegotiationInfoExtension $extension): bool
    {
        // 如果未启用安全重协商，直接返回失败
        if (!$this->secureRenegotiation) {
            return false;
        }
        
        // 初始握手，服务器应该提供空的重协商数据
        if (!$this->isRenegotiating) {
            return $extension->getRenegotiatedConnection() === '';
        }
        
        // 重协商时，服务器应该提供客户端和服务器的验证数据
        $expectedData = $this->clientVerifyData . $this->serverVerifyData;
        return $extension->getRenegotiatedConnection() === $expectedData;
    }
} 
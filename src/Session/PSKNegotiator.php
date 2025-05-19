<?php

namespace Tourze\TLSHandshake\Session;

/**
 * PSK协商器
 * 
 * 负责TLS 1.3中PSK身份和模式的选择与协商
 */
class PSKNegotiator
{
    /**
     * PSK处理器
     * 
     * @var PSKHandler
     */
    private PSKHandler $pskHandler;
    
    /**
     * 首选PSK模式
     * 
     * @var int
     */
    private int $preferredMode = TLS13PSKMode::PSK_DHE_KE;
    
    /**
     * 是否强制使用首选模式
     * 
     * @var bool
     */
    private bool $requirePreferredMode = false;
    
    /**
     * 协商后的PSK身份
     * 
     * @var string|null
     */
    private ?string $negotiatedPSK = null;
    
    /**
     * 协商后的PSK模式
     * 
     * @var int|null
     */
    private ?int $negotiatedMode = null;
    
    /**
     * 构造函数
     * 
     * @param PSKHandler $pskHandler PSK处理器
     */
    public function __construct(PSKHandler $pskHandler)
    {
        $this->pskHandler = $pskHandler;
    }
    
    /**
     * 选择最佳的PSK身份
     * 
     * 从客户端提供的PSK列表中选择第一个有效的PSK
     * 
     * @param array<string> $clientPSKs 客户端PSK身份列表
     * @return string|null 选择的PSK身份，无匹配则返回null
     */
    public function selectBestPSK(array $clientPSKs): ?string
    {
        foreach ($clientPSKs as $pskIdentity) {
            if ($this->pskHandler->hasPSK($pskIdentity)) {
                return $pskIdentity;
            }
        }
        
        return null;
    }
    
    /**
     * 选择最佳的PSK模式
     * 
     * 根据服务器首选和客户端支持的模式选择最佳PSK模式
     * 
     * @param array<int> $clientModes 客户端支持的PSK模式列表
     * @return int|null 选择的PSK模式，无匹配则返回null
     */
    public function selectBestPSKMode(array $clientModes): ?int
    {
        // 验证客户端模式列表中的每个模式
        $validClientModes = array_filter($clientModes, [TLS13PSKMode::class, 'isValidMode']);
        
        // 如果客户端提供的模式为空，则无法协商
        if (empty($validClientModes)) {
            return null;
        }
        
        // 如果首选模式在客户端支持的模式中
        if (in_array($this->preferredMode, $validClientModes)) {
            return $this->preferredMode;
        }
        
        // 如果强制使用首选模式，但客户端不支持，则返回null
        if ($this->requirePreferredMode) {
            return null;
        }
        
        // 否则选择客户端支持的第一个模式
        return $validClientModes[0];
    }
    
    /**
     * 设置首选PSK模式
     * 
     * @param int $mode PSK模式
     * @return self
     */
    public function setPreferredMode(int $mode): self
    {
        if (!TLS13PSKMode::isValidMode($mode)) {
            throw new \InvalidArgumentException('无效的PSK模式: ' . $mode);
        }
        
        $this->preferredMode = $mode;
        return $this;
    }
    
    /**
     * 设置是否强制使用首选模式
     * 
     * @param bool $require 是否强制
     * @return self
     */
    public function setRequirePreferredMode(bool $require): self
    {
        $this->requirePreferredMode = $require;
        return $this;
    }
    
    /**
     * 获取首选PSK模式
     * 
     * @return int 首选PSK模式
     */
    public function getPreferredMode(): int
    {
        return $this->preferredMode;
    }
    
    /**
     * 是否强制使用首选模式
     * 
     * @return bool 是否强制
     */
    public function isPreferredModeRequired(): bool
    {
        return $this->requirePreferredMode;
    }
    
    /**
     * 设置协商后的PSK身份
     * 
     * @param string|null $pskIdentity PSK身份
     * @return self
     */
    public function setNegotiatedPSK(?string $pskIdentity): self
    {
        $this->negotiatedPSK = $pskIdentity;
        return $this;
    }
    
    /**
     * 获取协商后的PSK身份
     * 
     * @return string|null PSK身份
     */
    public function getNegotiatedPSK(): ?string
    {
        return $this->negotiatedPSK;
    }
    
    /**
     * 设置协商后的PSK模式
     * 
     * @param int|null $mode PSK模式
     * @return self
     */
    public function setNegotiatedMode(?int $mode): self
    {
        $this->negotiatedMode = $mode;
        return $this;
    }
    
    /**
     * 获取协商后的PSK模式
     * 
     * @return int|null PSK模式
     */
    public function getNegotiatedMode(): ?int
    {
        return $this->negotiatedMode;
    }
    
    /**
     * 检查PSK协商是否成功
     * 
     * 协商成功需要同时具有有效的PSK身份和模式
     * 
     * @return bool 是否成功
     */
    public function isPSKNegotiationSuccessful(): bool
    {
        return $this->negotiatedPSK !== null && 
               $this->negotiatedMode !== null &&
               TLS13PSKMode::isValidMode($this->negotiatedMode);
    }
} 
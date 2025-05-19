<?php

namespace Tourze\TLSHandshake\Extension;

/**
 * 支持的组扩展
 * 
 * 此扩展在TLS 1.2中被称为"elliptic_curves"，在TLS 1.3中改名为"supported_groups"
 * 用于客户端告知服务器支持的椭圆曲线和有限域组
 * 
 * 参考：
 * - RFC 5246 (TLS 1.2) Section 7.4.1.4.1
 * - RFC 8446 (TLS 1.3) Section 4.2.7
 */
class SupportedGroupsExtension extends AbstractExtension
{
    /**
     * 支持的组列表
     *
     * @var array<int>
     */
    private array $groups = [];
    
    /**
     * 获取扩展类型
     * 
     * @return int 扩展类型值
     */
    public function getType(): int
    {
        return ExtensionType::SUPPORTED_GROUPS->value;
    }
    
    /**
     * 获取支持的组列表
     * 
     * @return array<int> 支持的组列表
     */
    public function getGroups(): array
    {
        return $this->groups;
    }
    
    /**
     * 设置支持的组列表
     * 
     * @param array<int> $groups 支持的组列表
     * @return self
     */
    public function setGroups(array $groups): self
    {
        $this->groups = $groups;
        return $this;
    }
    
    /**
     * 添加支持的组
     * 
     * @param int $group 组标识符
     * @return self
     */
    public function addGroup(int $group): self
    {
        if (!in_array($group, $this->groups, true)) {
            $this->groups[] = $group;
        }
        return $this;
    }
    
    /**
     * 将扩展编码为二进制数据
     * 
     * 格式：
     * struct {
     *     uint16 named_group_list_length;
     *     NamedGroup named_group_list[named_group_list_length];
     * } NamedGroupList;
     * 
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 组编码
        $groupsData = '';
        foreach ($this->groups as $group) {
            $groupsData .= $this->encodeUint16($group);
        }
        
        // 组列表长度（按字节计）
        $result = $this->encodeUint16(strlen($groupsData));
        
        // 组列表数据
        $result .= $groupsData;
        
        return $result;
    }
    
    /**
     * 从二进制数据解码扩展
     * 
     * @param string $data 二进制数据
     * @return static 解码后的扩展对象
     * @throws \InvalidArgumentException 如果数据格式无效
     */
    public static function decode(string $data): static
    {
        $extension = new static();
        $offset = 0;
        
        // 检查数据长度
        if (strlen($data) < 2) {
            throw new \InvalidArgumentException('SupportedGroups extension data too short');
        }
        
        // 组列表长度
        $groupsLength = self::decodeUint16($data, $offset);
        
        // 检查数据长度是否一致
        if ($offset + $groupsLength > strlen($data)) {
            throw new \InvalidArgumentException('SupportedGroups extension data length mismatch');
        }
        
        // 解析组列表
        $groupsEnd = $offset + $groupsLength;
        while ($offset < $groupsEnd) {
            // 确保有足够的数据来解析组
            if ($offset + 2 > $groupsEnd) {
                throw new \InvalidArgumentException('SupportedGroups extension group data incomplete');
            }
            
            // 解析组值
            $group = self::decodeUint16($data, $offset);
            
            // 添加组
            $extension->addGroup($group);
        }
        
        return $extension;
    }
    
    /**
     * 设置推荐的默认组
     * 
     * @return self
     */
    public function setRecommendedGroups(): self
    {
        $groups = [];
        foreach (NamedGroup::getRecommendedGroups() as $group) {
            $groups[] = $group->value;
        }
        return $this->setGroups($groups);
    }
}

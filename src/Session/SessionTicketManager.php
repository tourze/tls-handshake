<?php

namespace Tourze\TLSHandshake\Session;

/**
 * TLS会话票据管理器
 * 
 * 负责创建、验证和管理会话票据
 */
class SessionTicketManager
{
    /**
     * 票据密钥
     * 
     * @var array 包含密钥名称和实际密钥的数组
     */
    private array $ticketKeys = [];
    
    /**
     * 当前激活的票据密钥名称
     * 
     * @var string
     */
    private string $activeKeyName = '';
    
    /**
     * 票据生命周期（秒）
     * 
     * @var int
     */
    private int $ticketLifetime = 3600 * 24; // 默认24小时
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        // 生成初始密钥
        $this->generateNewKey();
    }
    
    /**
     * 生成新的票据密钥
     * 
     * @return string 新密钥的名称
     */
    public function generateNewKey(): string
    {
        // 生成16字节的随机密钥名称
        $keyName = bin2hex(random_bytes(8));
        
        // 生成32字节的加密密钥和32字节的HMAC密钥
        $encryptionKey = random_bytes(32);
        $hmacKey = random_bytes(32);
        
        $this->ticketKeys[$keyName] = [
            'encryption_key' => $encryptionKey,
            'hmac_key' => $hmacKey,
            'created_at' => time(),
        ];
        
        $this->activeKeyName = $keyName;
        
        return $keyName;
    }
    
    /**
     * 获取当前激活的票据密钥信息
     * 
     * @return array|null 密钥信息，不存在则返回null
     */
    public function getActiveKey(): ?array
    {
        if (!isset($this->ticketKeys[$this->activeKeyName])) {
            return null;
        }
        
        return [
            'name' => $this->activeKeyName,
            'key' => $this->ticketKeys[$this->activeKeyName],
        ];
    }
    
    /**
     * 根据密钥名称获取密钥信息
     * 
     * @param string $keyName 密钥名称
     * @return array|null 密钥信息，不存在则返回null
     */
    public function getKeyByName(string $keyName): ?array
    {
        if (!isset($this->ticketKeys[$keyName])) {
            return null;
        }
        
        return $this->ticketKeys[$keyName];
    }
    
    /**
     * 轮换密钥
     * 
     * @param int $maxKeys 保留的最大密钥数量
     * @return string 新激活的密钥名称
     */
    public function rotateKeys(int $maxKeys = 3): string
    {
        // 生成新密钥
        $this->generateNewKey();
        
        // 按创建时间排序密钥
        $keys = $this->ticketKeys;
        uasort($keys, function (array $a, array $b) {
            return $b['created_at'] <=> $a['created_at'];
        });
        
        // 仅保留最新的几个密钥
        $keysToKeep = array_slice(array_keys($keys), 0, $maxKeys, true);
        $newTicketKeys = [];
        
        foreach ($keysToKeep as $keyName) {
            $newTicketKeys[$keyName] = $this->ticketKeys[$keyName];
        }
        
        $this->ticketKeys = $newTicketKeys;
        
        return $this->activeKeyName;
    }
    
    /**
     * 创建会话票据
     * 
     * @param SessionInterface $session 会话对象
     * @return SessionTicket 票据对象
     */
    public function createTicket(SessionInterface $session): SessionTicket
    {
        $activeKey = $this->getActiveKey();
        
        if (!$activeKey) {
            throw new \RuntimeException('没有可用的票据密钥');
        }
        
        $keyName = $activeKey['name'];
        $encryptionKey = $activeKey['key']['encryption_key'];
        $hmacKey = $activeKey['key']['hmac_key'];
        
        // 生成随机IV
        $iv = random_bytes(16);
        
        // 提取会话数据
        $sessionData = [
            'session_id' => $session->getSessionId(),
            'cipher_suite' => $session->getCipherSuite(),
            'master_secret' => $session->getMasterSecret(),
            'creation_time' => $session->getCreationTime(),
        ];
        
        // 序列化会话状态 - 使用JSON格式避免PHP内部序列化格式可能引起的问题
        $sessionState = json_encode($sessionData);
        
        // 加密会话状态
        $encryptedState = openssl_encrypt(
            $sessionState,
            'aes-256-cbc',
            $encryptionKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($encryptedState === false) {
            throw new \RuntimeException('加密会话状态失败: ' . openssl_error_string());
        }
        
        // 计算HMAC
        $hmacData = $keyName . $iv . $encryptedState;
        $hmac = hash_hmac('sha256', $hmacData, $hmacKey, true);
        
        return new SessionTicket($keyName, $iv, $encryptedState, $hmac);
    }
    
    /**
     * 验证并解密票据
     * 
     * @param SessionTicket $ticket 票据对象
     * @return SessionInterface|null 会话对象，验证失败则返回null
     */
    public function decryptTicket(SessionTicket $ticket): ?SessionInterface
    {
        $keyName = $ticket->getKeyName();
        $iv = $ticket->getIV();
        $encryptedState = $ticket->getEncryptedState();
        $hmac = $ticket->getHMAC();
        
        // 获取密钥
        $key = $this->getKeyByName($keyName);
        
        if (!$key) {
            return null; // 未知密钥
        }
        
        $encryptionKey = $key['encryption_key'];
        $hmacKey = $key['hmac_key'];
        
        // 验证HMAC
        $hmacData = $keyName . $iv . $encryptedState;
        $expectedHmac = hash_hmac('sha256', $hmacData, $hmacKey, true);
        
        if (!hash_equals($expectedHmac, $hmac)) {
            return null; // HMAC验证失败
        }
        
        // 解密会话状态
        $sessionState = openssl_decrypt(
            $encryptedState,
            'aes-256-cbc',
            $encryptionKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($sessionState === false) {
            return null; // 解密失败
        }
        
        try {
            $state = json_decode($sessionState, true);
            
            if (!is_array($state) || empty($state)) {
                return null; // JSON解析失败或数据为空
            }
            
            // 验证所需字段是否存在
            if (!isset($state['session_id']) || !isset($state['cipher_suite']) || 
                !isset($state['master_secret']) || !isset($state['creation_time'])) {
                return null;
            }
            
            return new TLSSession(
                $state['session_id'],
                $state['cipher_suite'],
                $state['master_secret'],
                $state['creation_time']
            );
        } catch (\Exception $e) {
            return null; // 解析失败
        }
    }
    
    /**
     * 获取票据生命周期
     * 
     * @return int 票据生命周期（秒）
     */
    public function getTicketLifetime(): int
    {
        return $this->ticketLifetime;
    }
    
    /**
     * 设置票据生命周期
     * 
     * @param int $ticketLifetime 票据生命周期（秒）
     * @return self
     */
    public function setTicketLifetime(int $ticketLifetime): self
    {
        $this->ticketLifetime = $ticketLifetime;
        return $this;
    }
} 
<?php

namespace Tourze\TLSHandshake\Protocol;

use Tourze\TLSHandshake\Message\HandshakeMessageInterface;

/**
 * 消息序列化性能优化工具类
 * 
 * 提供高性能的TLS握手消息序列化和反序列化功能
 */
class MessageSerializer
{
    /**
     * 缓存大小限制（字节）
     */
    private const CACHE_SIZE_LIMIT = 1024 * 1024; // 1MB
    
    /**
     * 消息类型缓存
     * 
     * @var array<string, string>
     */
    private static array $encodeCache = [];
    
    /**
     * 当前缓存大小（字节）
     * 
     * @var int
     */
    private static int $currentCacheSize = 0;
    
    /**
     * 对消息进行高效序列化
     * 
     * @param HandshakeMessageInterface $message 要序列化的消息
     * @param bool $useCache 是否使用缓存
     * @return string 序列化后的二进制数据
     */
    public static function serializeMessage(
        HandshakeMessageInterface $message, 
        bool $useCache = true
    ): string {
        // 生成缓存键
        $cacheKey = null;
        
        // 只有不可变的消息类型才能使用缓存
        if ($useCache && self::canMessageBeCached($message)) {
            $cacheKey = self::generateCacheKey($message);
            
            // 检查缓存中是否有对应的序列化结果
            if (isset(self::$encodeCache[$cacheKey])) {
                return self::$encodeCache[$cacheKey];
            }
        }
        
        // 序列化消息
        $result = $message->encode();
        
        // 如果启用缓存且有缓存键，则将结果存入缓存
        if ($useCache && $cacheKey !== null) {
            self::cacheEncodedMessage($cacheKey, $result);
        }
        
        return $result;
    }
    
    /**
     * 批量序列化多个消息，提高性能
     * 
     * @param array<HandshakeMessageInterface> $messages 要序列化的消息数组
     * @param bool $useCache 是否使用缓存
     * @return array<string> 序列化后的二进制数据数组
     */
    public static function serializeMessages(
        array $messages, 
        bool $useCache = true
    ): array {
        $results = [];
        
        foreach ($messages as $message) {
            $results[] = self::serializeMessage($message, $useCache);
        }
        
        return $results;
    }
    
    /**
     * 清除序列化缓存
     */
    public static function clearCache(): void
    {
        self::$encodeCache = [];
        self::$currentCacheSize = 0;
    }
    
    /**
     * 生成消息的缓存键
     * 
     * @param HandshakeMessageInterface $message 消息对象
     * @return string 缓存键
     */
    private static function generateCacheKey(HandshakeMessageInterface $message): string
    {
        $messageType = $message->getType();
        $serialized = serialize($message);
        return $messageType->value . '_' . md5($serialized);
    }
    
    /**
     * 判断消息是否可以被缓存
     * 
     * @param HandshakeMessageInterface $message 消息对象
     * @return bool 是否可缓存
     */
    private static function canMessageBeCached(HandshakeMessageInterface $message): bool
    {
        $messageType = $message->getType();
        
        // 这些消息类型通常包含不可变的内容，适合缓存
        $cacheableTypes = [
            HandshakeMessageType::HELLO_REQUEST,
            HandshakeMessageType::SERVER_HELLO_DONE,
            // 可以根据实际情况添加其他适合缓存的消息类型
        ];
        
        return in_array($messageType, $cacheableTypes);
    }
    
    /**
     * 将编码后的消息存入缓存
     * 
     * @param string $key 缓存键
     * @param string $data 序列化后的数据
     */
    private static function cacheEncodedMessage(string $key, string $data): void
    {
        $dataSize = strlen($data);
        
        // 如果当前缓存已经接近或超过限制，清理部分缓存
        if (self::$currentCacheSize + $dataSize > self::CACHE_SIZE_LIMIT) {
            self::evictCache($dataSize);
        }
        
        // 添加到缓存
        self::$encodeCache[$key] = $data;
        self::$currentCacheSize += $dataSize;
    }
    
    /**
     * 缓存淘汰策略，清理部分缓存
     * 
     * @param int $requiredSpace 需要的空间大小
     */
    private static function evictCache(int $requiredSpace): void
    {
        // 如果缓存过大，直接清空重新开始
        if ($requiredSpace > self::CACHE_SIZE_LIMIT / 2) {
            self::clearCache();
            return;
        }
        
        // 否则移除一些缓存项，直到有足够空间
        $spaceToFree = self::$currentCacheSize + $requiredSpace - self::CACHE_SIZE_LIMIT;
        
        if ($spaceToFree <= 0) {
            return;
        }
        
        $freedSpace = 0;
        foreach (self::$encodeCache as $key => $data) {
            $dataSize = strlen($data);
            unset(self::$encodeCache[$key]);
            $freedSpace += $dataSize;
            self::$currentCacheSize -= $dataSize;
            
            if ($freedSpace >= $spaceToFree) {
                break;
            }
        }
    }
    
    /**
     * 优化二进制数据的拼接操作
     * 
     * @param array<string> $chunks 要拼接的二进制数据块
     * @return string 拼接后的结果
     */
    public static function optimizedConcat(array $chunks): string
    {
        $totalSize = 0;
        foreach ($chunks as $chunk) {
            $totalSize += strlen($chunk);
        }
        
        // 对于小数据量，直接使用字符串连接
        if ($totalSize < 8192) {
            return implode('', $chunks);
        }
        
        // 对于大数据量，使用字符串缓冲区
        $output = '';
        $buffer = '';
        $bufferSize = 0;
        
        foreach ($chunks as $chunk) {
            $chunkSize = strlen($chunk);
            
            // 如果当前缓冲区+新块超过8KB，先刷新缓冲区
            if ($bufferSize + $chunkSize > 8192) {
                $output .= $buffer;
                $buffer = '';
                $bufferSize = 0;
            }
            
            $buffer .= $chunk;
            $bufferSize += $chunkSize;
        }
        
        // 添加剩余的缓冲区数据
        if ($bufferSize > 0) {
            $output .= $buffer;
        }
        
        return $output;
    }
    
    /**
     * 针对握手消息的高效率解析
     * 
     * @param string $data 二进制数据
     * @param string $messageClass 消息类的完全限定名
     * @return HandshakeMessageInterface 解析后的消息对象
     */
    public static function efficientDecode(string $data, string $messageClass): HandshakeMessageInterface
    {
        if (!is_subclass_of($messageClass, HandshakeMessageInterface::class)) {
            throw new \InvalidArgumentException("Class must implement HandshakeMessageInterface");
        }
        
        return $messageClass::decode($data);
    }
} 
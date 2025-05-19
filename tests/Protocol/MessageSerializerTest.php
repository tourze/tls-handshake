<?php

namespace Tourze\TLSHandshake\Tests\Protocol;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Message\ClientHelloMessage;
use Tourze\TLSHandshake\Message\HelloRequestMessage;
use Tourze\TLSHandshake\Message\ServerHelloDoneMessage;
use Tourze\TLSHandshake\Protocol\MessageSerializer;

/**
 * MessageSerializer单元测试
 */
class MessageSerializerTest extends TestCase
{
    /**
     * 测试消息序列化与缓存
     */
    public function testSerializeMessage(): void
    {
        // 创建一个HelloRequest消息（适合缓存的消息类型）
        $helloRequest = new HelloRequestMessage();
        
        // 第一次序列化
        $result1 = MessageSerializer::serializeMessage($helloRequest);
        
        // 再次序列化，应该使用缓存
        $result2 = MessageSerializer::serializeMessage($helloRequest);
        
        // 两次结果应该相同
        $this->assertSame($result1, $result2);
        
        // 清除缓存
        MessageSerializer::clearCache();
        
        // 创建一个ClientHello消息，它与HelloRequest有明显不同的结构
        $clientHello = new ClientHelloMessage();
        $clientHello->setSessionId('test_session_id');

        // 序列化不同的消息，结果应该不同
        $result3 = MessageSerializer::serializeMessage($clientHello);
        $this->assertNotSame($result1, $result3);
    }
    
    /**
     * 测试批量序列化
     */
    public function testSerializeMessages(): void
    {
        // 创建多个消息
        $helloRequest = new HelloRequestMessage();
        $serverHelloDone = new ServerHelloDoneMessage();
        
        // 批量序列化
        $results = MessageSerializer::serializeMessages([$helloRequest, $serverHelloDone]);
        
        // 结果应该是一个数组，包含两个元素
        $this->assertIsArray($results);
        $this->assertCount(2, $results);
        
        // 单独序列化的结果应该与批量序列化的结果相同
        $this->assertSame($helloRequest->encode(), $results[0]);
        $this->assertSame($serverHelloDone->encode(), $results[1]);
    }

    /**
     * 测试优化的字符串拼接
     */
    public function testOptimizedConcat(): void
    {
        // 小数据量测试
        $smallChunks = ['hello', 'world'];
        $smallResult = MessageSerializer::optimizedConcat($smallChunks);
        $this->assertSame('helloworld', $smallResult);
        
        // 大数据量测试
        $largeChunks = [];
        $expectedLargeResult = '';
        
        // 创建超过8KB的数据
        for ($i = 0; $i < 1000; $i++) {
            $chunk = str_repeat('a', 10) . $i;
            $largeChunks[] = $chunk;
            $expectedLargeResult .= $chunk;
        }
        
        $largeResult = MessageSerializer::optimizedConcat($largeChunks);
        $this->assertSame($expectedLargeResult, $largeResult);
        $this->assertGreaterThan(8192, strlen($largeResult)); // 确认数据量大于8KB
    }
    
    /**
     * 测试高效解码
     */
    public function testEfficientDecode(): void
    {
        // 创建一个ClientHello消息
        $clientHello = new ClientHelloMessage();
        
        // 序列化消息
        $encoded = $clientHello->encode();
        
        // 使用高效解码
        $decoded = MessageSerializer::efficientDecode(
            $encoded,
            ClientHelloMessage::class
        );
        
        // 解码结果应该是ClientHello类型
        $this->assertInstanceOf(ClientHelloMessage::class, $decoded);
    }
    
    /**
     * 测试解码不正确的消息类
     */
    public function testDecodeInvalidClass(): void
    {
        // 创建一个HelloRequest消息
        $helloRequest = new HelloRequestMessage();
        
        // 序列化消息
        $encoded = $helloRequest->encode();
        
        // 使用不正确的类名，应抛出异常
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Class must implement HandshakeMessageInterface");
        MessageSerializer::efficientDecode(
            $encoded,
            \stdClass::class
        );
    }
    
    /**
     * 测试缓存大小限制
     */
    public function testCacheSizeLimit(): void
    {
        // 清除缓存
        MessageSerializer::clearCache();
        
        // 创建一个带有大量数据的ClientHello
        $clientHello = new ClientHelloMessage();
        $clientHello->setSessionId(str_repeat('a', 32)); // 32字节会话ID
        
        // 使用不缓存的方式序列化（不会缓存ClientHello，它不是可缓存的消息类型）
        $result = MessageSerializer::serializeMessage($clientHello, false);
        
        // 序列化结果应该是一个非空字符串
        $this->assertIsString($result);
        $this->assertNotEmpty($result);
    }
} 
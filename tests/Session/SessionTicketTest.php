<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Session\SessionTicket;

/**
 * 会话票据测试
 */
class SessionTicketTest extends TestCase
{
    /**
     * 测试票据基本功能
     */
    public function testBasicTicketFunctionality(): void
    {
        $keyName = str_pad('test_key', 16, "\0");
        $iv = random_bytes(16);
        $encryptedState = random_bytes(64);
        $hmac = random_bytes(32);
        
        $ticket = new SessionTicket($keyName, $iv, $encryptedState, $hmac);
        
        // 验证基本属性
        $this->assertEquals($keyName, $ticket->getKeyName());
        $this->assertEquals($iv, $ticket->getIV());
        $this->assertEquals($encryptedState, $ticket->getEncryptedState());
        $this->assertEquals($hmac, $ticket->getHMAC());
        
        // 测试设置新值
        $newKeyName = str_pad('new_key', 16, "\0");
        $newIv = random_bytes(16);
        $newEncryptedState = random_bytes(64);
        $newHmac = random_bytes(32);
        
        $ticket->setKeyName($newKeyName)
            ->setIV($newIv)
            ->setEncryptedState($newEncryptedState)
            ->setHMAC($newHmac);
        
        $this->assertEquals($newKeyName, $ticket->getKeyName());
        $this->assertEquals($newIv, $ticket->getIV());
        $this->assertEquals($newEncryptedState, $ticket->getEncryptedState());
        $this->assertEquals($newHmac, $ticket->getHMAC());
    }
    
    /**
     * 测试票据编码和解码
     */
    public function testTicketEncodeAndDecode(): void
    {
        $keyName = str_pad('test_key', 16, "\0");
        $iv = random_bytes(16);
        $encryptedState = random_bytes(64);
        $hmac = random_bytes(32);
        
        $ticket = new SessionTicket($keyName, $iv, $encryptedState, $hmac);
        
        // 编码票据
        $encoded = $ticket->encode();
        
        // 验证编码结果
        $this->assertNotEmpty($encoded);
        $this->assertIsString($encoded);
        
        // 解码票据
        $decoded = SessionTicket::decode($encoded);
        
        // 验证解码结果
        $this->assertInstanceOf(SessionTicket::class, $decoded);
        $this->assertEquals($keyName, $decoded->getKeyName());
        $this->assertEquals($iv, $decoded->getIV());
        $this->assertEquals($encryptedState, $decoded->getEncryptedState());
        $this->assertEquals($hmac, $decoded->getHMAC());
    }
    
    /**
     * 测试解码无效票据
     */
    public function testDecodeInvalidTicket(): void
    {
        // 测试数据太短
        $this->expectException(\InvalidArgumentException::class);
        SessionTicket::decode(random_bytes(20));
    }
    
    /**
     * 测试解码长度不一致的票据
     */
    public function testDecodeInconsistentLengthTicket(): void
    {
        // 创建有效票据但长度字段不匹配实际数据
        $keyName = str_pad('test_key', 16, "\0");
        $iv = random_bytes(16);
        
        // 创建有效编码但状态长度字段超过实际数据的票据
        $data = $keyName . $iv . chr(0xFF) . chr(0xFF) . random_bytes(10);
        
        $this->expectException(\InvalidArgumentException::class);
        SessionTicket::decode($data);
    }
    
    /**
     * 测试不同状态长度的票据编解码
     */
    public function testVariousStateLengths(): void
    {
        $keyName = str_pad('test_key', 16, "\0");
        $iv = random_bytes(16);
        $hmac = random_bytes(32);
        
        // 测试不同大小的加密状态
        $sizes = [10, 100, 1000, 10000];
        
        foreach ($sizes as $size) {
            $encryptedState = random_bytes($size);
            $ticket = new SessionTicket($keyName, $iv, $encryptedState, $hmac);
            
            // 编码并解码
            $encoded = $ticket->encode();
            $decoded = SessionTicket::decode($encoded);
            
            // 验证状态大小正确
            $this->assertEquals($size, strlen($decoded->getEncryptedState()));
            $this->assertEquals($encryptedState, $decoded->getEncryptedState());
        }
    }
} 
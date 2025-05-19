<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Session\PSKHandler;
use Tourze\TLSHandshake\Session\TLS13PSKSession;

class PSKHandlerTest extends TestCase
{
    private PSKHandler $pskHandler;

    protected function setUp(): void
    {
        $this->pskHandler = new PSKHandler();
    }

    public function testRegisterAndRetrievePSK(): void
    {
        // 测试注册和检索PSK
        $identity = 'test-identity';
        $key = random_bytes(32);
        
        $this->pskHandler->registerPSK($identity, $key);
        
        $retrievedKey = $this->pskHandler->getPSK($identity);
        $this->assertEquals($key, $retrievedKey, '检索到的PSK应与注册的相同');
    }
    
    public function testHasPSK(): void
    {
        $identity = 'test-identity';
        $key = random_bytes(32);
        
        $this->assertFalse($this->pskHandler->hasPSK($identity), '未注册的PSK身份应返回false');
        
        $this->pskHandler->registerPSK($identity, $key);
        $this->assertTrue($this->pskHandler->hasPSK($identity), '已注册的PSK身份应返回true');
    }
    
    public function testRemovePSK(): void
    {
        $identity = 'test-identity';
        $key = random_bytes(32);
        
        $this->pskHandler->registerPSK($identity, $key);
        $this->assertTrue($this->pskHandler->hasPSK($identity));
        
        $this->pskHandler->removePSK($identity);
        $this->assertFalse($this->pskHandler->hasPSK($identity), '移除后的PSK不应存在');
    }
    
    public function testBindSessionToPSK(): void
    {
        $identity = 'test-identity';
        $key = random_bytes(32);
        $session = $this->createMock(TLS13PSKSession::class);
        
        $this->pskHandler->registerPSK($identity, $key);
        $this->pskHandler->bindSessionToPSK($identity, $session);
        
        $boundSession = $this->pskHandler->getSessionByPSK($identity);
        $this->assertSame($session, $boundSession, '应返回绑定到PSK的会话');
    }
    
    public function testGetUnboundSession(): void
    {
        $identity = 'test-identity';
        
        $boundSession = $this->pskHandler->getSessionByPSK($identity);
        $this->assertNull($boundSession, '未绑定的PSK应返回null');
    }
}

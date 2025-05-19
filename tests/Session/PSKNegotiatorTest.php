<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Session\PSKHandler;
use Tourze\TLSHandshake\Session\PSKNegotiator;
use Tourze\TLSHandshake\Session\TLS13PSKMode;

class PSKNegotiatorTest extends TestCase
{
    private PSKNegotiator $negotiator;
    private PSKHandler $pskHandler;
    
    protected function setUp(): void
    {
        $this->pskHandler = new PSKHandler();
        $this->negotiator = new PSKNegotiator($this->pskHandler);
        
        // 设置一些测试PSK
        $this->pskHandler->registerPSK('psk-id-1', random_bytes(32));
        $this->pskHandler->registerPSK('psk-id-2', random_bytes(32));
        $this->pskHandler->registerPSK('psk-id-3', random_bytes(32));
    }
    
    public function testSelectBestPSK(): void
    {
        // 模拟客户端提供的PSK身份列表
        $clientPSKs = ['unknown-psk', 'psk-id-2', 'psk-id-1'];
        
        $selectedPSK = $this->negotiator->selectBestPSK($clientPSKs);
        $this->assertSame('psk-id-2', $selectedPSK, '应选择客户端PSK中第一个匹配的有效PSK');
    }
    
    public function testSelectBestPSKWithNoMatch(): void
    {
        // 无匹配PSK身份的情况
        $clientPSKs = ['unknown-psk-1', 'unknown-psk-2'];
        
        $selectedPSK = $this->negotiator->selectBestPSK($clientPSKs);
        $this->assertNull($selectedPSK, '无匹配PSK时应返回null');
    }
    
    public function testSelectBestPSKMode(): void
    {
        // 模拟客户端支持的PSK模式
        $clientModes = [TLS13PSKMode::PSK_DHE_KE, TLS13PSKMode::PSK_KE];
        
        // 配置服务器首选PSK_DHE_KE模式
        $this->negotiator->setPreferredMode(TLS13PSKMode::PSK_DHE_KE);
        
        $selectedMode = $this->negotiator->selectBestPSKMode($clientModes);
        $this->assertSame(TLS13PSKMode::PSK_DHE_KE, $selectedMode, '应选择首选的PSK_DHE_KE模式');
        
        // 配置服务器首选PSK_KE模式
        $this->negotiator->setPreferredMode(TLS13PSKMode::PSK_KE);
        
        $selectedMode = $this->negotiator->selectBestPSKMode($clientModes);
        $this->assertSame(TLS13PSKMode::PSK_KE, $selectedMode, '应选择首选的PSK_KE模式');
    }
    
    public function testSelectBestPSKModeWithNoMatch(): void
    {
        // 客户端只支持PSK_KE，但服务器配置为只接受PSK_DHE_KE
        $clientModes = [TLS13PSKMode::PSK_KE];
        $this->negotiator->setPreferredMode(TLS13PSKMode::PSK_DHE_KE);
        $this->negotiator->setRequirePreferredMode(true);
        
        $selectedMode = $this->negotiator->selectBestPSKMode($clientModes);
        $this->assertNull($selectedMode, '当强制首选模式且无匹配时应返回null');
        
        // 但如果不强制首选模式，应选择客户端支持的模式
        $this->negotiator->setRequirePreferredMode(false);
        $selectedMode = $this->negotiator->selectBestPSKMode($clientModes);
        $this->assertSame(TLS13PSKMode::PSK_KE, $selectedMode, '不强制首选模式时应选择客户端支持的模式');
    }
    
    public function testIsPSKNegotiationSuccessful(): void
    {
        // 模拟成功的PSK协商
        $this->negotiator->setNegotiatedPSK('psk-id-1');
        $this->negotiator->setNegotiatedMode(TLS13PSKMode::PSK_DHE_KE);
        
        $this->assertTrue($this->negotiator->isPSKNegotiationSuccessful(), '协商成功时应返回true');
        
        // 模拟失败的PSK协商
        $this->negotiator->setNegotiatedPSK(null);
        $this->assertFalse($this->negotiator->isPSKNegotiationSuccessful(), '协商失败时应返回false');
        
        $this->negotiator->setNegotiatedPSK('psk-id-1');
        $this->negotiator->setNegotiatedMode(null);
        $this->assertFalse($this->negotiator->isPSKNegotiationSuccessful(), '协商失败时应返回false');
    }
} 
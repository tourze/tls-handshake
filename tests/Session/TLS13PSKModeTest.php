<?php

namespace Tourze\TLSHandshake\Tests\Session;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Session\TLS13PSKMode;

class TLS13PSKModeTest extends TestCase
{
    public function testPSKModeConstants(): void
    {
        // 测试PSK模式常量
        $this->assertSame(0, TLS13PSKMode::PSK_KE, 'PSK_KE模式应为0');
        $this->assertSame(1, TLS13PSKMode::PSK_DHE_KE, 'PSK_DHE_KE模式应为1');
    }
    
    public function testIsValidMode(): void
    {
        // 测试有效模式验证
        $this->assertTrue(TLS13PSKMode::isValidMode(TLS13PSKMode::PSK_KE), 'PSK_KE应为有效模式');
        $this->assertTrue(TLS13PSKMode::isValidMode(TLS13PSKMode::PSK_DHE_KE), 'PSK_DHE_KE应为有效模式');
        $this->assertFalse(TLS13PSKMode::isValidMode(2), '2应为无效模式');
        $this->assertFalse(TLS13PSKMode::isValidMode(-1), '-1应为无效模式');
    }
    
    public function testGetModeName(): void
    {
        // 测试获取模式名称
        $this->assertSame('psk_ke', TLS13PSKMode::getModeName(TLS13PSKMode::PSK_KE), 'PSK_KE模式名称应为psk_ke');
        $this->assertSame('psk_dhe_ke', TLS13PSKMode::getModeName(TLS13PSKMode::PSK_DHE_KE), 'PSK_DHE_KE模式名称应为psk_dhe_ke');
        $this->assertSame('unknown', TLS13PSKMode::getModeName(99), '未知模式应返回unknown');
    }
    
    public function testIsPSKOnlyMode(): void
    {
        // 测试是否为仅PSK模式
        $this->assertTrue(TLS13PSKMode::isPSKOnlyMode(TLS13PSKMode::PSK_KE), 'PSK_KE是仅PSK模式');
        $this->assertFalse(TLS13PSKMode::isPSKOnlyMode(TLS13PSKMode::PSK_DHE_KE), 'PSK_DHE_KE不是仅PSK模式');
    }
    
    public function testGetAllModes(): void
    {
        // 测试获取所有模式
        $allModes = TLS13PSKMode::getAllModes();
        $this->assertCount(2, $allModes, '应有2个PSK模式');
        $this->assertContains(TLS13PSKMode::PSK_KE, $allModes, '模式列表应包含PSK_KE');
        $this->assertContains(TLS13PSKMode::PSK_DHE_KE, $allModes, '模式列表应包含PSK_DHE_KE');
    }
}

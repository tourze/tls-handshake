<?php

namespace Tourze\TLSHandshake\Tests\Extension;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Extension\ExtensionType;
use Tourze\TLSHandshake\Extension\PreSharedKeyExtension;
use Tourze\TLSHandshake\Extension\PSKIdentity;

/**
 * PSK扩展测试类
 */
class PreSharedKeyExtensionTest extends TestCase
{
    /**
     * 测试扩展类型是否正确
     */
    public function testType(): void
    {
        $extension = new PreSharedKeyExtension();
        $this->assertEquals(ExtensionType::PRE_SHARED_KEY->value, $extension->getType());
    }
    
    /**
     * 测试设置和获取PSK标识列表
     */
    public function testSetAndGetIdentities(): void
    {
        $extension = new PreSharedKeyExtension();
        
        // 测试默认值
        $this->assertEmpty($extension->getIdentities());
        
        // 创建测试标识
        $identity1 = new PSKIdentity();
        $identity1->setIdentity(hex2bin('abcd'));
        $identity1->setObfuscatedTicketAge(1000);
        
        $identity2 = new PSKIdentity();
        $identity2->setIdentity(hex2bin('1234'));
        $identity2->setObfuscatedTicketAge(2000);
        
        // 测试设置标识
        $identities = [$identity1, $identity2];
        $extension->setIdentities($identities);
        $this->assertEquals($identities, $extension->getIdentities());
        
        // 测试添加标识
        $extension = new PreSharedKeyExtension();
        $extension->addIdentity($identity1);
        $this->assertCount(1, $extension->getIdentities());
        $this->assertEquals($identity1, $extension->getIdentities()[0]);
    }
    
    /**
     * 测试设置和获取PSK绑定器列表
     */
    public function testSetAndGetBinders(): void
    {
        $extension = new PreSharedKeyExtension();
        
        // 测试默认值
        $this->assertEmpty($extension->getBinders());
        
        // 测试设置绑定器
        $binders = [hex2bin('aa'), hex2bin('bb')];
        $extension->setBinders($binders);
        $this->assertEquals($binders, $extension->getBinders());
        
        // 测试添加绑定器
        $extension = new PreSharedKeyExtension();
        $extension->addBinder(hex2bin('cc'));
        $this->assertCount(1, $extension->getBinders());
        $this->assertEquals(hex2bin('cc'), $extension->getBinders()[0]);
    }
    
    /**
     * 测试客户端格式的编码和解码
     */
    public function testClientEncodeAndDecode(): void
    {
        $originalExtension = new PreSharedKeyExtension();
        
        // 创建测试标识和绑定器
        $identity = new PSKIdentity();
        $identity->setIdentity(hex2bin('abcd'));
        $identity->setObfuscatedTicketAge(1000);
        $originalExtension->addIdentity($identity);
        
        $originalExtension->addBinder(hex2bin('1234'));
        
        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedExtension = PreSharedKeyExtension::decode($encodedData);
        
        // 验证解码后的扩展
        $this->assertCount(1, $decodedExtension->getIdentities());
        $decodedIdentity = $decodedExtension->getIdentities()[0];
        $this->assertEquals(hex2bin('abcd'), $decodedIdentity->getIdentity());
        $this->assertEquals(1000, $decodedIdentity->getObfuscatedTicketAge());
        
        $this->assertCount(1, $decodedExtension->getBinders());
        $this->assertEquals(hex2bin('1234'), $decodedExtension->getBinders()[0]);
    }
    
    /**
     * 测试服务器格式的编码和解码
     */
    public function testServerEncodeAndDecode(): void
    {
        $originalExtension = new PreSharedKeyExtension(true);
        $originalExtension->setSelectedIdentity(2);
        
        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertNotEmpty($encodedData);
        
        // 解码
        $decodedExtension = PreSharedKeyExtension::decode($encodedData, true);
        
        // 验证解码后的扩展
        $this->assertTrue($decodedExtension->isServerFormat());
        $this->assertEquals(2, $decodedExtension->getSelectedIdentity());
    }
    
    /**
     * 测试客户端编码格式是否符合RFC规范
     */
    public function testClientEncodeFormat(): void
    {
        $extension = new PreSharedKeyExtension();
        
        // 创建测试标识和绑定器
        $identity = new PSKIdentity();
        $identity->setIdentity(hex2bin('ab'));
        $identity->setObfuscatedTicketAge(1000);
        $extension->addIdentity($identity);
        
        $extension->addBinder(hex2bin('cd'));
        
        $encoded = $extension->encode();
        
        // 客户端扩展数据应为：
        // - 2字节的标识列表长度 (0008) - 8字节
        // - 2字节的标识长度 (0002) - 2字节
        // - 标识数据 (ab)
        // - 4字节的票据年龄 (000003e8) - 1000
        // - 2字节的绑定器列表长度 (0004) - 4字节
        // - 1字节的绑定器长度 (01) - 1字节
        // - 绑定器数据 (cd)
        $expected = hex2bin('0008') . hex2bin('0002') . hex2bin('ab') . hex2bin('000003e8') .
                   hex2bin('0004') . hex2bin('01') . hex2bin('cd');
        
        $this->assertEquals($expected, $encoded);
    }
    
    /**
     * 测试服务器编码格式是否符合RFC规范
     */
    public function testServerEncodeFormat(): void
    {
        $extension = new PreSharedKeyExtension(true);
        $extension->setSelectedIdentity(2);
        
        $encoded = $extension->encode();
        
        // 服务器扩展数据应为：
        // - 2字节的选定标识索引 (0002)
        $expected = hex2bin('0002');
        
        $this->assertEquals($expected, $encoded);
    }
    
    /**
     * 测试解码无效数据时的异常处理
     */
    public function testDecodeInvalidData(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        
        // 创建无效的客户端数据 (标识列表长度字段表示有4个字节的数据，但实际只有2个字节)
        $invalidData = hex2bin('0004') . hex2bin('0000');
        
        PreSharedKeyExtension::decode($invalidData);
    }
    
    /**
     * 测试TLS版本兼容性
     */
    public function testVersionCompatibility(): void
    {
        $extension = new PreSharedKeyExtension();
        
        // 此扩展仅适用于TLS 1.3
        $this->assertFalse($extension->isApplicableForVersion('1.2'));
        $this->assertTrue($extension->isApplicableForVersion('1.3'));
    }
}

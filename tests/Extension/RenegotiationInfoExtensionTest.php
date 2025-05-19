<?php

namespace Tourze\TLSHandshake\Tests\Extension;

use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshake\Extension\ExtensionType;
use Tourze\TLSHandshake\Extension\RenegotiationInfoExtension;

/**
 * 安全重协商扩展测试类
 */
class RenegotiationInfoExtensionTest extends TestCase
{
    /**
     * 测试创建基本的扩展对象
     */
    public function testBasicExtensionCreation(): void
    {
        $extension = new RenegotiationInfoExtension();
        $this->assertEquals(ExtensionType::RENEGOTIATION_INFO->value, $extension->getType());
        $this->assertEmpty($extension->getRenegotiatedConnection());
    }

    /**
     * 测试设置和获取重协商连接数据
     */
    public function testSetAndGetRenegotiatedConnection(): void
    {
        $renegotiatedConnection = random_bytes(24);
        $extension = new RenegotiationInfoExtension();
        $extension->setRenegotiatedConnection($renegotiatedConnection);
        $this->assertEquals($renegotiatedConnection, $extension->getRenegotiatedConnection());
    }

    /**
     * 测试序列化和反序列化
     */
    public function testSerializeAndDeserialize(): void
    {
        // 测试空的重协商信息
        $extension1 = new RenegotiationInfoExtension();
        $data1 = $extension1->encode();
        $decoded1 = RenegotiationInfoExtension::decode($data1);
        $this->assertEquals('', $decoded1->getRenegotiatedConnection());
        
        // 测试带有重协商数据的情况
        $renegotiatedConnection = random_bytes(24);
        $extension2 = new RenegotiationInfoExtension();
        $extension2->setRenegotiatedConnection($renegotiatedConnection);
        $data2 = $extension2->encode();
        $decoded2 = RenegotiationInfoExtension::decode($data2);
        $this->assertEquals($renegotiatedConnection, $decoded2->getRenegotiatedConnection());
    }
    
    /**
     * 测试非法数据
     */
    public function testInvalidData(): void
    {
        // 测试无效的长度前缀
        $invalidData = chr(0xFF) . random_bytes(10);
        $this->expectException(\InvalidArgumentException::class);
        RenegotiationInfoExtension::decode($invalidData);
    }
} 
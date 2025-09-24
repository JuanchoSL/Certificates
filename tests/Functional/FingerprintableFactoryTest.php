<?php

namespace JuanchoSL\Certificates\Tests\Functional;

use JuanchoSL\Certificates\Factories\ContainerFactory;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;
use PHPUnit\Framework\TestCase;
class FingerprintableFactoryTest extends TestCase
{

    protected $extractor;
    protected function providerData($cache): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            PublicKeyContainer::class => [$dir . 'certificates-ssh.pub'],
            CertificateContainer::class => [$dir . 'ca.crt'],
        ];
    }

    public function setUp(): void
    {
        $this->extractor = new ContainerFactory();
    }
    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByUnknow($provider)
    {
        $entity = $this->extractor->createFromUnknow($provider);
        echo "";
        $this->assertInstanceOf(FingerprintReadableInterface::class, $entity);
    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByFile($provider)
    {
        $entity = $this->extractor->createFromFile($provider);
        $this->assertInstanceOf(FingerprintReadableInterface::class, $entity);

    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByString($provider)
    {
        $entity = $this->extractor->createFromString(file_get_contents($provider));
        $this->assertInstanceOf(FingerprintReadableInterface::class, $entity);

    }
}
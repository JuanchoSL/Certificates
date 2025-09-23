<?php

namespace JuanchoSL\Certificates\Tests\Functional;

use JuanchoSL\Certificates\Factories\ContainerFactory;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Repositories\PEMContainer;
use JuanchoSL\Certificates\Repositories\Pkcs7Container;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use PHPUnit\Framework\TestCase;
class PublicBundlesFactoryTest extends TestCase
{

    protected $extractor;
    protected function providerData($cache): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            Pkcs7Container::class => [$dir . 'certificates.p7b'],
            Pkcs8Container::class => [$dir . 'certificates.p8'],
            PEMContainer::class => [$dir . 'certificates.pem'],
            /*
            Pkcs12Container::class => [$dir . 'certificates.p12'],
            CertificateContainer::class => [$dir . 'ca.crt'],
            */
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
        $this->assertInstanceOf(CertificateReadableInterface::class, $entity);
        $this->assertInstanceOf(ChainReadableInterface::class, $entity);
    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByFile($provider)
    {
        $entity = $this->extractor->createFromFile($provider);
        $this->assertInstanceOf(CertificateReadableInterface::class, $entity);
        $this->assertInstanceOf(ChainReadableInterface::class, $entity);
    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByString($provider)
    {
        $entity = $this->extractor->createFromString(file_get_contents($provider));
        $this->assertInstanceOf(CertificateReadableInterface::class, $entity);
        $this->assertInstanceOf(ChainReadableInterface::class, $entity);
    }
}
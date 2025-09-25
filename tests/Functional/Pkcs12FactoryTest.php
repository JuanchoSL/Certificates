<?php

namespace JuanchoSL\Certificates\Tests\Functional;

use JuanchoSL\Certificates\Factories\ContainerFactory;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Interfaces\PrivateKeyReadableInterface;
use JuanchoSL\Certificates\Repositories\LockedContainer;
use JuanchoSL\Certificates\Repositories\Pkcs12Container;
use PHPUnit\Framework\TestCase;

class Pkcs12FactoryTest extends TestCase
{

    protected $extractor;
    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            Pkcs12Container::class => [$dir . 'certificates.p12'],
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
        $this->assertInstanceOf(LockedContainer::class, $entity);

        $entity = $entity(getenv('CRYPT_PASSWORD'));
        $this->assertInstanceOf(CertificateReadableInterface::class, $entity);
        $this->assertInstanceOf(ChainReadableInterface::class, $entity);
        $this->assertInstanceOf(PrivateKeyReadableInterface::class, $entity);
    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByFile($provider)
    {

        $entity = $this->extractor->createFromFile($provider);
        $this->assertInstanceOf(LockedContainer::class, $entity);

        $entity = $entity(getenv('CRYPT_PASSWORD'));
        $this->assertInstanceOf(CertificateReadableInterface::class, $entity);
        $this->assertInstanceOf(ChainReadableInterface::class, $entity);
        $this->assertInstanceOf(PrivateKeyReadableInterface::class, $entity);

    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByString($provider)
    {
        $entity = $this->extractor->createFromContents(file_get_contents($provider));
        $this->assertInstanceOf(LockedContainer::class, $entity);

        $entity = $entity(getenv('CRYPT_PASSWORD'));
        $this->assertInstanceOf(CertificateReadableInterface::class, $entity);
        $this->assertInstanceOf(ChainReadableInterface::class, $entity);
        $this->assertInstanceOf(PrivateKeyReadableInterface::class, $entity);

    }
}
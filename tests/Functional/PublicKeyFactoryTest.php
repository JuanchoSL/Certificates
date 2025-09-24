<?php

namespace JuanchoSL\Certificates\Tests\Functional;

use JuanchoSL\Certificates\Factories\ContainerFactory;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use PHPUnit\Framework\TestCase;
class PublicKeyFactoryTest extends TestCase
{

    protected $extractor;
    protected function providerData($cache): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            PrivateKeyContainer::class => [$dir . 'certificates.key'],
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
        $this->assertInstanceOf(PublicKeyReadableInterface::class, $entity);
    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByFile($provider)
    {
        $entity = $this->extractor->createFromFile($provider);
        $this->assertInstanceOf(PublicKeyReadableInterface::class, $entity);

    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByString($provider)
    {
        $entity = $this->extractor->createFromString(file_get_contents($provider));
        $this->assertInstanceOf(PublicKeyReadableInterface::class, $entity);

    }
}
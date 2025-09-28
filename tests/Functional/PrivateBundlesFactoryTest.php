<?php

namespace JuanchoSL\Certificates\Tests\Functional;

use JuanchoSL\Certificates\Factories\ContainerFactory;
use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Interfaces\PrivateKeyReadableInterface;
use JuanchoSL\Certificates\Repositories\LockedContainer;
use JuanchoSL\Certificates\Repositories\PEMContainer;
use JuanchoSL\Certificates\Repositories\Pkcs12Container;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use PHPUnit\Framework\TestCase;

class PrivateBundlesFactoryTest extends TestCase
{

    protected $extractor;
    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            Pkcs8Container::class => [$dir . 'certificates.p8'],
            PEMContainer::class => [$dir . 'certificates.pem'],
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
        if ($entity instanceof LockedContainer) {
            $entity = $entity(getenv('CRYPT_PASSWORD'));
        }
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
        if ($entity instanceof LockedContainer) {
            $entity = $entity(getenv('CRYPT_PASSWORD'));
        }
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
        if ($entity instanceof LockedContainer) {
            $entity = $entity(getenv('CRYPT_PASSWORD'));
        }
        $this->assertInstanceOf(CertificateReadableInterface::class, $entity);
        $this->assertInstanceOf(ChainReadableInterface::class, $entity);
        $this->assertInstanceOf(PrivateKeyReadableInterface::class, $entity);

    }
}
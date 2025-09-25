<?php

namespace JuanchoSL\Certificates\Tests\Functional;

use JuanchoSL\Certificates\Factories\ContainerFactory;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicSshKeyContainer;
use PHPUnit\Framework\TestCase;
class DetailablesFactoryTest extends TestCase
{

    protected $extractor;
    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
                /*
                Pkcs7Container::class => [$dir . 'certificates.p7b'],
                Pkcs8Container::class => [$dir . 'certificates.p8'],
                PEMContainer::class => [$dir . 'certificates.pem'],
                Pkcs12Container::class => [$dir . 'certificates.p12'],
                */
            PrivateKeyContainer::class => [$dir . 'certificates.key'],
            PublicKeyContainer::class => [$dir . 'certificates.pub'],
            PublicSshKeyContainer::class => [$dir . 'certificates-ssh.pub'],
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
        $this->assertInstanceOf(DetailableInterface::class, $entity);
    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByFile($provider)
    {
        $entity = $this->extractor->createFromFile($provider);
        $this->assertInstanceOf(DetailableInterface::class, $entity);

    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByString($provider)
    {
        $entity = $this->extractor->createFromContents(file_get_contents($provider));
        $this->assertInstanceOf(DetailableInterface::class, $entity);

    }
}
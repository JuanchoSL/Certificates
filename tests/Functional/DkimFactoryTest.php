<?php

namespace JuanchoSL\Certificates\Tests\Functional;

use JuanchoSL\Certificates\Factories\ContainerFactory;
use JuanchoSL\Certificates\Factories\DnsDkimFactory;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\DkimContainer;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;
use PHPUnit\Framework\TestCase;
class DkimFactoryTest extends TestCase
{

    protected $extractor;
    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            PrivateKeyContainer::class => [$dir . 'certificates.key'],
            CertificateContainer::class => [$dir . 'ca.crt'],
        ];
    }

    public function setUp(): void
    {
        $this->extractor = new DnsDkimFactory();
    }
    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByParent($provider)
    {
        $provider = (new ContainerFactory())->createFromFile($provider);
        $entity = $this->extractor->createFromPublicKeyReadable($provider);
        $this->assertInstanceOf(DkimContainer::class, $entity);
    }

    /**
     * @dataProvider providerData
     */
    public function testOpenContainerByFile($provider)
    {
        $entity = $this->extractor->createFromFile($provider);
        $this->assertInstanceOf(DkimContainer::class, $entity);

    }

    public function testOpenContainerByString()
    {
        $entity = file_get_contents(implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.pub']));
        $entity = $this->extractor->createFromPublicKeyString($entity);
        $this->assertInstanceOf(DkimContainer::class, $entity);

    }
    public function testOpenContainerByContainer()
    {
        $entity = new PublicKeyContainer(implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.pub']));
        $entity = $this->extractor->createFromPublicKeyContainer($entity);
        $this->assertInstanceOf(DkimContainer::class, $entity);
    }
}
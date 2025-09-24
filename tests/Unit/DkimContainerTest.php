<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use JuanchoSL\Certificates\Factories\DnsDkimFactory;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;
use PHPUnit\Framework\TestCase;
use Stringable;

class DkimContainerTest extends TestCase
{

    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'Pubf' => [$dir . 'certificates.pub'],
            'Pubs' => [file_get_contents($dir . 'certificates.pub')],
            'Pub' => [(string) (new PublicKeyContainer($dir . 'certificates.pub'))],
        ];
    }

    protected function providerDataPublic(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'Pubf' => [$dir . 'certificates.pub'],
            'Pubs' => [file_get_contents($dir . 'certificates.pub')],
            'Pub' => [(string) (new PublicKeyContainer($dir . 'certificates.pub'))],
        ];
    }

    protected function providerDataReadable(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'Prvf' => [$dir . 'certificates.key'],
            'Prvs' => [file_get_contents($dir . 'certificates.key')],
            'Prv' => [(string) (new PrivateKeyContainer($dir . 'certificates.key'))],
        ];
    }


    /**
     * @dataProvider providerData
     */
    public function testReadContainerDkim($cert)
    {
        $cert = (new DnsDkimFactory)->createFromPublicKeyString($cert);

        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
    }
    /**
     * @dataProvider providerDataPublic
     */
    public function testReadContainerPublic($cert)
    {
        $cert = (new PublicKeyContainer($cert))->getDkim();

        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
    }

    /**
     * @dataProvider providerDataReadable
     */
    public function testReadContainerPublicReadable($cert)
    {
        $cert = (new PrivateKeyContainer($cert))->getPublicKey()->getDkim();

        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
    }
}
<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\PublicSshKeyContainer;
use PHPUnit\Framework\TestCase;
use Stringable;

class PublicSshKeyTest extends TestCase
{

    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'Pubf' => [$dir . 'certificates-ssh.pub'],
            'Pubs' => [file_get_contents($dir . 'certificates-ssh.pub')],
            'Pub' => [(string) (new PublicSshKeyContainer($dir . 'certificates-ssh.pub'))],
        ];
    }


    /**
     * @dataProvider providerData
     */
    public function testReadContainer($cert)
    {
        $cert = new PublicSshKeyContainer($cert);
        $this->assertNotInstanceOf(PublicKeyReadableInterface::class, $cert);
        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(SaveableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
        $this->assertInstanceOf(FingerprintReadableInterface::class, $cert);
        $this->assertInstanceOf(FormateableInterface::class, $cert);
    }
}
<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordProtectableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordUnprotectableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Repositories\PEMContainer;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use PHPUnit\Framework\TestCase;
use Stringable;

class PrivateKeyTest extends TestCase
{

    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'Keyf' => [$dir . 'certificates.key'],
            'Keys' => [file_get_contents($dir . 'certificates.key')],
            'Key' => [(string) new PrivateKeyContainer($dir . 'certificates.key')],
            'Pem' => [(string) (new PEMContainer($dir . 'certificates.pem'))->getPrivateKey()],
            'Bundle8' => [(string) (new Pkcs8Container($dir . 'certificates.p8'))->getPrivateKey()],
        ];
    }


    /**
     * @dataProvider providerData
     */
    public function testReadContainer($cert)
    {
        $cert = new PrivateKeyContainer($cert);
        $this->assertInstanceOf(PublicKeyReadableInterface::class, $cert);
        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(SaveableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(StandarizableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
        $this->assertInstanceOf(PasswordUnprotectableInterface::class, $cert);
        $this->assertNotInstanceOf(FingerprintReadableInterface::class, $cert);
        $this->assertNotInstanceOf(PasswordProtectableInterface::class, $cert);
    }
}
<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\Pkcs7Container;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;
use PHPUnit\Framework\TestCase;
use Stringable;

class PublicKeyTest extends TestCase
{

    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'Pubf' => [$dir . 'certificates.pub'],
            'Pubs' => [file_get_contents($dir . 'certificates.pub')],
            'Pub' => [(string) (new PublicKeyContainer($dir . 'certificates.pub'))],
            'Priv' => [(string) (new PrivateKeyContainer($dir . 'certificates.key'))->getPublicKey()],
            'Cert' => [(string) (new CertificateContainer($dir . 'ca.crt'))->getPublicKey()],
            'Bundle7' => [(string) (new Pkcs7Container($dir . 'certificates.p7b'))->getCertificate()->getPublicKey()],
            'Bundle8' => [(string) (new Pkcs8Container($dir . 'certificates.p8'))->getCertificate()->getPublicKey()],
        ];
    }


    /**
     * @dataProvider providerData
     */
    public function testReadContainer($cert)
    {
        $cert = new PublicKeyContainer($cert);
        $this->assertNotInstanceOf(PublicKeyReadableInterface::class, $cert);
        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(SaveableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(StandarizableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
    }
}
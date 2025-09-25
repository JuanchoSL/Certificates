<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\Pkcs12Container;
use JuanchoSL\Certificates\Repositories\Pkcs7Container;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use PHPUnit\Framework\TestCase;
use Stringable;

class CertificateTest extends TestCase
{

    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'Cerft' => [$dir . 'ca.crt'],
            'Certs' => [file_get_contents($dir . 'ca.crt')],
            'Cert' => [(string) new CertificateContainer($dir . 'ca.crt')],
            'Bundle7' => [(string) (new Pkcs7Container($dir . 'certificates.p7b'))->getCertificate()],
            'Bundle8' => [(string) (new Pkcs8Container($dir . 'certificates.p8'))->getCertificate()],
            'Bundle12' => [(string) (new Pkcs12Container($dir . 'certificates.p12', getenv('CRYPT_PASSWORD')))->getCertificate()],
        ];
    }


    /**
     * @dataProvider providerData
     */
    public function testReadContainer($cert)
    {
        $cert = new CertificateContainer($cert);
        $this->assertInstanceOf(PublicKeyReadableInterface::class, $cert);
        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(SaveableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(StandarizableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
        $this->assertInstanceOf(FingerprintReadableInterface::class, $cert);
    }
}
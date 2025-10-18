<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use Countable;
use Iterator;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\CrlContainer;
use PHPUnit\Framework\TestCase;
use Stringable;

class CrlTest extends TestCase
{

    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'path' => [$dir . 'revoked.crl'],
            'contents' => [file_get_contents($dir . 'revoked.crl')],
            'stringable' => [(string) new CrlContainer($dir . 'revoked.crl')],
            'exportable' => [(new CrlContainer($dir . 'revoked.crl'))->export()],
        ];
    }

    /**
     * @dataProvider providerData
     */
    public function testReadContainer($cert)
    {
        $cert = new CrlContainer($cert);
        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(SaveableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
        $this->assertInstanceOf(Countable::class, $cert);
        $this->assertInstanceOf(Iterator::class, $cert);
    }
    /**
     * @dataProvider providerData
     */
    public function testReadContents($cert)
    {
        $cert = new CrlContainer($cert);
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']);
        $subject = (new CertificateContainer($dir . DIRECTORY_SEPARATOR . "certificates.crt"));
        $this->assertTrue($cert->hasCertificate($subject), "Certificate is included");
        $this->assertTrue($cert->hasSerial(intval($subject->getDetail('serialNumber'))), "Serial is included");
        $this->assertTrue($cert->isRevokedByCert($subject), "Certificate is revoked");
        $this->assertTrue($cert->isRevokedBySerial(intval($subject->getDetail('serialNumber'))), "Serial is revoked");
    }
}
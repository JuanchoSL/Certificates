<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\Pkcs12Container;
use PHPUnit\Framework\TestCase;

class Pkcs12SelfSignedTest extends TestCase
{

    public function testReadContainer()
    {
        $file = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'localhost.p12']);
        $pkcs = new Pkcs12Container($file, 'localhost');
        $private = $pkcs->getPrivateKey();
        $this->assertNotFalse($private, "Check than container have a private key available");
        $cert = $pkcs->getCertificate();
        $this->assertEquals('localhost', $cert->getDetail('subject')['commonName'], "The common name is correct");
        $public = $cert->getPublicKey();
        $this->assertTrue($cert->checkIssuerByPublicKey($public), message: "Check than cert has been signed from the related private key ussing issuer public key");
    }

    public function testFailIssuer()
    {
        $issuer = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'ca.crt']);
        $issuer = new CertificateContainer($issuer);

        $file = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'localhost.p12']);
        $pkcs = new Pkcs12Container($file, 'localhost');

        $this->assertFalse($pkcs->getCertificate()->checkIssuerByPublicKey($issuer->getPublicKey()), message: "Check than cert has been signed from the related private key ussing issuer public key");
    }
}
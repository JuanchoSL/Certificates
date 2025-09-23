<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\Pkcs7Container;
use PHPUnit\Framework\TestCase;

class Pkcs7Test extends TestCase
{

    public function testReadContainer()
    {
        $issuer = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'ca.crt']);
        $issuer = new CertificateContainer($issuer);

        $bundle = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.p7b']);
        $pkcs = new Pkcs7Container($bundle);

        $cert = $pkcs->getCertificate();
        $this->assertEquals('certificates', $cert->getDetail('subject')['commonName'], "The common name is correct");
        $this->assertEquals($issuer->getDetail('subject')['commonName'], $cert->getDetail('issuer')['commonName'], "The common name is correct for the issuer");

        $public_issuer = $issuer->getPublicKey();
        $this->assertTrue($cert->checkIssuerByPublicKey($public_issuer), message: "Check than cert has been signed from the related private key ussing issuer public key");
    }

    public function testCheckIssuer()
    {
        $issuer = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'ca.crt']);
        $issuer = new CertificateContainer($issuer);

        $bundle = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.p7b']);
        $pkcs = new Pkcs7Container($bundle);

        $cert = $pkcs->getCertificate();
        $this->assertEquals($issuer->getDetail('subject')['commonName'], $cert->getDetail('issuer')['commonName'], "The common name is correct for the issuer");

        $public_issuer = $issuer->getPublicKey();
        $this->assertTrue($cert->checkIssuerByPublicKey($public_issuer), message: "Check than cert has been signed from the related private key ussing issuer public key");
    }

    public function testCheckChain()
    {
        $bundle = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.p7b']);
        $pkcs = new Pkcs7Container($bundle);

        $chain = $pkcs->getChain();
        $this->assertNotEmpty($chain, "The bundle have a chain and is not empty");
        $this->assertIsIterable($chain, "The bundle have a chain and is iterable");
        $this->assertContainsOnlyInstancesOf(CertificateContainer::class, $chain, "The chain cntains only certificates containers");
    }
}
<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use JuanchoSL\Certificates\Interfaces\CertificateReadableInterface;
use JuanchoSL\Certificates\Interfaces\ChainReadableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordUnprotectableInterface;
use JuanchoSL\Certificates\Interfaces\PrivateKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

class Pkcs8Test extends TestCase
{

    public function testReadContainer()
    {
        $bundle = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.p8']);
        $cert = new Pkcs8Container($bundle);
        $this->assertInstanceOf(CertificateReadableInterface::class, $cert);
        $this->assertInstanceOf(ChainReadableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(FormateableInterface::class, $cert);
        $this->assertInstanceOf(PrivateKeyReadableInterface::class, $cert);
        $this->assertInstanceOf(SaveableInterface::class, $cert);
        $this->assertNotInstanceOf(FingerprintReadableInterface::class, $cert);
        $this->assertNotInstanceOf(PasswordUnprotectableInterface::class, $cert);
    }
    public function testReadContainerData()
    {
        $issuer = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'ca.crt']);
        $issuer = new CertificateContainer($issuer);

        $bundle = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.p8']);
        $pkcs = new Pkcs8Container($bundle);

        $private = $pkcs->getPrivateKey();
        $this->assertNotFalse($private, "Check than container have a private key available");
        $this->assertInstanceOf(PrivateKeyContainer::class, $private, "Check than container have a private key available");
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $private(), "Check than container have a private key instantiable");

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

        $bundle = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.p8']);
        $pkcs = new Pkcs8Container($bundle);

        $cert = $pkcs->getCertificate();
        $this->assertEquals($issuer->getDetail('subject')['commonName'], $cert->getDetail('issuer')['commonName'], "The common name is correct for the issuer");

        $public_issuer = $issuer->getPublicKey();
        $this->assertTrue($cert->checkIssuerByPublicKey($public_issuer), message: "Check than cert has been signed from the related private key ussing issuer public key");
    }

    public function testCheckChain()
    {
        $bundle = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data', 'certificates.p8']);
        $pkcs = new Pkcs8Container($bundle);

        $chain = $pkcs->getChain();
        $this->assertNotEmpty($chain, "The bundle have a chain and is not empty");
        $this->assertIsIterable($chain, "The bundle have a chain and is iterable");
        $this->assertContainsOnlyInstancesOf(CertificateContainer::class, $chain, "The chain cntains only certificates containers");
    }
}
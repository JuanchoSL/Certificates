<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;

interface CertificateReadableInterface
{

    /**
     * Retrieve the included x509 Certificate Container
     * @return CertificateInterface
     */
    public function getCertificate(): CertificateInterface;
}
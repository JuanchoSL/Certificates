<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Repositories\CertificateContainer;

interface CertificateReadableInterface
{

    /**
     * Retrieve the included x509 Certificate Container
     * @return CertificateContainer
     */
    public function getCertificate(): CertificateContainer;
}
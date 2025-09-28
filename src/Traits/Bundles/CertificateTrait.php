<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits\Bundles;

use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;

trait CertificateTrait
{

    protected ?CertificateInterface $cert = null;

    public function getCertificate(): CertificateInterface
    {
        return $this->cert;
    }
}
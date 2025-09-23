<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits\Bundles;

use JuanchoSL\Certificates\Repositories\CertificateContainer;

trait CertificateTrait
{

    protected $cert = null;

    public function getCertificate(): CertificateContainer
    {
        return $this->cert;
    }
}
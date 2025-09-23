<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;
use JuanchoSL\Certificates\Repositories\Pkcs8Container;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;

class Pkcs8Filler extends Pkcs8Container
{

    private $private;

    public function __construct(#[\SensitiveParameter] PrivateKeyContainer $private)
    {
        $this->private = $private;
    }

    public function setCertificate(CertificateContainer $certificate): static
    {
        $this->cert = $certificate;
        return $this;
    }
    public function setExtraCertificates(ChainContainer $certificates): static
    {
        $this->extras = $certificates;
        return $this;
    }

    public function export(): string
    {
        if (empty($this->pkcs8)) {
            $this->pkcs8 = (string) (new Pkcs8Creator())->setPrivateKey($this->private)->setCertificate($this->cert)->setExtraCertificates($this->extras);
        }
        return parent::export();
    }
}
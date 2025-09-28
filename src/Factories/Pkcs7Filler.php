<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;
use JuanchoSL\Certificates\Repositories\Pkcs7Container;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;

class Pkcs7Filler extends Pkcs7Container
{

    private $key;

    public function __construct(#[\SensitiveParameter] PrivateKeyContainer $private)
    {
        $this->key = $private;
    }

    public function setCertificate(CertificateContainer $certificate): static
    {
        $this->cert = $certificate;
        return $this;
    }
    public function setChain(ChainContainer $certificates): static
    {
        $this->chain = $certificates;
        return $this;
    }

    public function export(): string
    {
        if (empty($this->pkcs7)) {
            $this->pkcs7 = (string) (new Pkcs7Creator())->setPrivateKey($this->key)->setCertificate($this->getCertificate())->setChain($this->getChain());
        }
        return parent::export();
    }
}
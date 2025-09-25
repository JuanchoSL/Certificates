<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits\Bundles;

use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;

trait ChainTrait
{
    protected $chain = [];

    public function getChain(): ChainContainer
    {
        return $this->chain;
    }

    protected function certsShorting($data, bool $desc = true)
    {
        $extras = [];
        $last = '';

        if (count($data) > 1) {
            do {
                foreach ($data as $key => $cert) {
                    if (!$cert instanceof CertificateContainer) {
                        $cert = new CertificateContainer($cert);
                    }
                    $compare = (empty($last)) ? $cert->getPublicKey() : $last;
                    if ($cert->checkIssuerByPublicKey($compare)) {
                        $extras[] = (string) $cert;
                        $last = $cert->getPublicKey();
                        unset($data[$key]);
                        continue;
                    }
                }
            } while (!empty($data));
        } else {
            $extras = $data;
        }
        if (!$desc) {
            $extras = array_reverse($extras);
        }
        return $extras;
    }

}
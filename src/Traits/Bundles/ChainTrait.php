<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits\Bundles;

use JuanchoSL\Certificates\Interfaces\Complex\ChainInterface;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;

trait ChainTrait
{
    protected ?ChainInterface $chain = null;

    public function getChain(): ChainInterface
    {
        return $this->chain ?? new ChainContainer([]);
    }

    protected function certsShorting($data, bool $asc = true)
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
        if ($asc) {
            $extras = array_reverse($extras);
        }
        return $extras;
    }

}
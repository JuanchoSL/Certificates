<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits\Bundles;

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
                foreach ($data as $key => $crt) {
                    $x509 = openssl_x509_read($crt);
                    $details = openssl_x509_parse($x509);
                    $compare = (empty($last)) ? $details['subject']['CN'] : $last;
                    if ($details['issuer']['CN'] == $compare) {
                        $extras[] = $crt;
                        $last = $details['subject']['CN'];
                        unset($data[$key]);
                        continue;
                    }
                }
            } while (!empty($data));
        }
        if (!$desc) {
            $extras = array_reverse($extras);
        }
        return $extras;
    }

}
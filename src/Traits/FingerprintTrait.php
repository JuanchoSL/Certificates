<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

use Exception;

trait FingerprintTrait
{
    public function getFingerprint(string $algo, bool $hex): bool|string
    {
        $alloweds = openssl_get_md_methods();
        if (!in_array($algo, $alloweds)) {
            throw new Exception("The {$algo} hashing algorithm is not a valid value");
        }
        $key = $this->export();
        if (($fingerprint = openssl_digest($key, $algo, !$hex)) !== false && !$hex) {
            $fingerprint = base64_encode($fingerprint);
        }
        return $fingerprint ?? false;
    }

}
<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface FingerprintReadableInterface
{

    /**
     * Retrieve the fingerprint or hashing representation of the element
     * @return string The hash
     */
    public function getFingerprint(string $hash_algo): bool|string;
}
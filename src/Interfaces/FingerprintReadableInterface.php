<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface FingerprintReadableInterface
{

    /**
     * Retrieve the fingerprint or hashing representation of the element
     * @param string $hash_algo A valid algorithm, one included into openssl_get_md_methods
     * @param bool $hex True if we want the headecimal response, false for base64 encode of binary data
     * @return string The hash or false if have errors
     */
    public function getFingerprint(string $hash_algo, bool $hex): bool|string;
}
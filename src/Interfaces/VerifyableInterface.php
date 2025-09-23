<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\PublicKeyContainer;

interface VerifyableInterface
{

    /**
     * Verify the digital signature against a public key
     * @param \JuanchoSL\Certificates\Repositories\PublicKeyContainer $public
     * @return bool
     */
    public function checkIssuerByPublicKey(PublicKeyContainer $public): bool;

    /**
     * Checks if a private key corresponds to a certificate
     * @param \JuanchoSL\Certificates\Repositories\PrivateKeyContainer $private
     * @return bool
     */
    public function checkSubjectPrivateKey(#[\SensitiveParameter] PrivateKeyContainer $private): bool;
}
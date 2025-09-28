<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Interfaces\Complex\PublicKeyInterface;

interface PublicKeyReadableInterface
{

    /**
     * Retrieve the included Async Public Key Container
     * @return PublicKeyInterface
     */
    public function getPublicKey(): PublicKeyInterface;
}
<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Repositories\PublicKeyContainer;

interface PublicKeyReadableInterface
{

    /**
     * Retrieve the included Async Public Key Container
     * @return PublicKeyContainer
     */
    public function getPublicKey(): PublicKeyContainer;
}
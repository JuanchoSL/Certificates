<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;

interface PrivateKeyReadableInterface
{

    /**
     * Retrieve the included Async Private Key Container
     * @param string $password The password, if needed, in order to open the element
     * @return PrivateKeyContainer
     */
    public function getPrivateKey(?string $password = null): PrivateKeyContainer;
}
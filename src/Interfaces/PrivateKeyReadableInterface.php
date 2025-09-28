<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Interfaces\Complex\PrivateKeyInterface;

interface PrivateKeyReadableInterface
{

    /**
     * Retrieve the included Async Private Key Container
     * @param string $password The password, if needed, in order to open the element
     * @return PrivateKeyInterface
     */
    public function getPrivateKey(#[\SensitiveParameter] ?string $password = null): PrivateKeyInterface;
}
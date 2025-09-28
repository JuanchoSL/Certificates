<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Interfaces\Complex\ChainInterface;

interface ChainReadableInterface
{

    /**
     * Retrieve a Certificate Container Collection as a Chain Container iterable object
     * @return ChainInterface
     */
    public function getChain(): ChainInterface;
}
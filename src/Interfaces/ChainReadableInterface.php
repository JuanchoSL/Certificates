<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Repositories\ChainContainer;

interface ChainReadableInterface
{

    /**
     * Retrieve a Certificate Container Collection as a Chain Container iterable object
     * @return ChainContainer
     */
    public function getChain(): ChainContainer;
}
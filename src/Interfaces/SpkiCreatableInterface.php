<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

use JuanchoSL\Certificates\Repositories\PublicSpkiKeyContainer;

interface SpkiCreatableInterface
{

    /**
     * Returns the contents of the element
     * @return mixed The element contents
     */
    public function getSpkiKey(string $challenge): PublicSpkiKeyContainer;
}
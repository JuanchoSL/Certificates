<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface ExportableInterface
{

    /**
     * Returns the contents of the element
     * @return mixed The element contents
     */
    public function export(): mixed;
}
<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface SaveableInterface
{

    /**
     * Save the element into a file
     * @param mixed $fullpath The path to save or null for generate into temporal system folder and returning from reference
     * @return bool Operation result
     */
    public function save(?string &$fullpath = null): bool;
}
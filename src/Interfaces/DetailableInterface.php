<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface DetailableInterface
{

    /**
     * Read and return a detail from element
     * @param string $key The name of the detail to read
     * @return mixed The detail or false if not exists
     */
    public function getDetail(string $key): mixed;

    /**
     * Returns all the details of the element
     * @return mixed The detail value or false if not exists
     */
    public function getDetails(): array|false;
}
<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface StandarizableInterface
{

    /**
     * Return an openssl standard object
     * @return mixed The standard openssl object
     */
    public function __invoke(): mixed;
}
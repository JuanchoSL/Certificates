<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface FormateableInterface
{

    public function getExtension(): string;

    public function getMediaType(): string;
}
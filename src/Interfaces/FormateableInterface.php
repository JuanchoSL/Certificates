<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces;

interface FormateableInterface
{

    /**
     * Returns the standard entension for the file
     * @return string The mime extension
     */
    public function getExtension(): string;


    /**
     * Returns the standard mimetype for the file
     * @return string The mime type
     */
    public function getMediaType(): string;
}
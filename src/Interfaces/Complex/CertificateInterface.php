<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces\Complex;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Interfaces\VerifyableInterface;
use Stringable;

interface CertificateInterface extends DetailableInterface, ExportableInterface, SaveableInterface,
    StandarizableInterface, Stringable, PublicKeyReadableInterface, FingerprintReadableInterface, FormateableInterface, VerifyableInterface
{
}
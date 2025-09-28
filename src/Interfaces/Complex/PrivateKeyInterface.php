<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces\Complex;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordUnprotectableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use Stringable;

interface PrivateKeyInterface extends PasswordUnprotectableInterface,
    DetailableInterface,
    PublicKeyReadableInterface, ExportableInterface, SaveableInterface, Stringable, StandarizableInterface, FormateableInterface
{

}
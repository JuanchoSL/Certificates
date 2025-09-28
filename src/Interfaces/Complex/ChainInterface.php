<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Interfaces\Complex;

use Countable;
use Iterator;
use Stringable;
use JuanchoSL\Certificates\Interfaces\FormateableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;

interface ChainInterface extends Stringable,
    Iterator,
    Countable,
    SaveableInterface,
    FormateableInterface
{

}
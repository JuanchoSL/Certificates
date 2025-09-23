<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use Stringable;

/**
 * https://www.the-art-of-web.com/php/dkim-mail-signature/#google_vignette
 */
class DkimContainer implements DetailableInterface, Stringable, ExportableInterface
{

    use DetailableTrait, StringableTrait;

    protected $data = null;

    public function __construct(string $fullpath)
    {
        if (is_file($fullpath) && file_exists($fullpath)) {
            $fullpath = file_get_contents($fullpath);
        }
        $this->data = $fullpath;
    }

    public function getDetails(): array|false
    {
        list($selector, $register, $register_type, $values) = explode("\t", $this->data, 4);
        $values = explode(";", trim($values, '"'));
        foreach ($values as $key => $data) {
            list($name, $val) = explode("=", $data = trim($data), 2);
            $values[$name] = $val;
            unset($values[$key]);
        }
        return compact(['selector', 'register', 'register_type', 'values']);
    }

    public function export(): mixed
    {
        return $this->data;
    }

}
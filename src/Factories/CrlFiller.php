<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use Countable;
use DateTimeImmutable;
use DateTimeInterface;
use Iterator;
use Stringable;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\CrlContainer;
use JuanchoSL\Certificates\Enums\RevokeReasonsEnum;
use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;

class CrlFiller extends CrlContainer implements Iterator, Countable, Stringable, SaveableInterface, DetailableInterface
{

    public function __construct(string $cert_contents = '')
    {
        if (!empty($cert_contents)) {
            parent::__construct($cert_contents);
        }
    }

    public function addRevocation(CertificateInterface $cert, ?DateTimeInterface $revoke_time = null, ?RevokeReasonsEnum $revoke_reason = null): static
    {
        if (!$this->updated) {
            $this->number += 1;
            $this->updated = true;
        }
        if (is_null($revoke_time)) {
            $time = (is_null($revoke_reason)) ? intval($cert->getDetail('validTo_time_t')) : time();
            $revoke_time = DateTimeImmutable::createFromTimestamp($time);
        }
        return $this->appendConvertedData(intval($cert->getDetail('serialNumber')), $revoke_time, $revoke_reason);
    }

}
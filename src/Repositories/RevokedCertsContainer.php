<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Countable;
use DateTimeInterface;
use Iterator;
use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;

class RevokedCertsContainer implements Iterator, Countable
{

    protected array|CertificateInterface $certs = [];

    public function addRevocation(CertificateInterface $cert, DateTimeInterface $revoke_time, ?string $revoke_reason = null): static
    {
        $this->certs[] = [
            'cert' => $cert,
            'rev_date' => $revoke_time,
            'reason' => $revoke_reason
        ];
        return $this;
    }

    function rewind(): void
    {
        reset($this->certs);
    }

    function current(): mixed
    {
        return current($this->certs);
    }

    function key(): int|string|null
    {
        return key($this->certs);
    }

    function next(): void
    {
        next($this->certs);
    }

    function valid(): bool
    {
        return key($this->certs) !== null;
    }

    public function count(): int
    {
        return count($this->certs);
    }

}
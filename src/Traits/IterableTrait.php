<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

trait IterableTrait
{

    protected iterable $iterable = [];
    public function rewind(): void
    {
        reset($this->iterable);
    }
    public function current(): mixed
    {
        return current($this->iterable);
    }
    public function key(): int|string|null
    {
        return key($this->iterable);
    }
    public function next(): void
    {
        next($this->iterable);
    }
    public function valid(): bool
    {
        return key($this->iterable) !== null;
    }

    public function count(): int
    {
        return count($this->iterable);
    }
}
<?php

namespace App\Services\Workspaces;

/**
 * Source that already exists on disk — a developer pointing the scanner at a
 * working copy, or a checkout a previous scan left cached.
 *
 * Never deletes anything on release(): this path belongs to someone else.
 */
final class LocalPathWorkspace implements SourceWorkspace
{
    public function __construct(private string $absolutePath) {}

    public function path(): string
    {
        return $this->absolutePath;
    }

    public function isAvailable(): bool
    {
        return is_dir($this->absolutePath) && is_readable($this->absolutePath);
    }

    public function driver(): string
    {
        return 'local';
    }

    public function release(): void
    {
        // Caller-owned directory — deleting it would destroy a developer's
        // working copy.
    }
}

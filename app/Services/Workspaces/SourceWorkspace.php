<?php

namespace App\Services\Workspaces;

/**
 * A checked-out copy of the source a scan refers to.
 *
 * The app is deployed away from the code it analyses, so "the project
 * folder" is never simply present — it has to be acquired per scan. This
 * interface is the seam that lets the ingestion pipeline stay identical
 * whether the source arrived by git clone on a hosted server or is just a
 * directory on a developer's laptop.
 *
 * Implementations must be safe to release() more than once.
 */
interface SourceWorkspace
{
    /**
     * Absolute path to the source root.
     *
     * May point at a path that does not exist when the workspace is
     * unavailable; callers should check isAvailable() when they need to
     * know, since feature extraction degrades gracefully either way.
     */
    public function path(): string;

    /**
     * Whether real source is present at path().
     */
    public function isAvailable(): bool;

    /**
     * Short identifier for logs and the scan record, e.g. "git", "local".
     */
    public function driver(): string;

    /**
     * Release any resources. For ephemeral workspaces this deletes the
     * checkout; for a developer's local directory it does nothing.
     */
    public function release(): void;
}

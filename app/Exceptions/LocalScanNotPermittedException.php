<?php

namespace App\Exceptions;

use RuntimeException;

/**
 * Thrown when a browser-initiated scan targets a path this installation is
 * not permitted to read — disabled entirely, missing, or outside the
 * configured allowlist.
 */
class LocalScanNotPermittedException extends RuntimeException {}

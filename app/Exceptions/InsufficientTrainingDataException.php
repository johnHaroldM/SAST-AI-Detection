<?php

namespace App\Exceptions;

use RuntimeException;

/**
 * Thrown when a training run is requested before enough human-confirmed
 * labels exist, or before both classes are represented in the label set.
 *
 * Distinct from a genuine training failure: this is the expected state
 * during cold start, so callers report it as guidance rather than an error.
 */
class InsufficientTrainingDataException extends RuntimeException {}

<?php

namespace App\Services\AI;

use RuntimeException;

/**
 * Ollama itself is unavailable, so additional reviewer calls are unlikely
 * to succeed until the local runtime recovers.
 */
class OllamaUnavailableException extends RuntimeException {}

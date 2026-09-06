<?php

namespace App\Services\AI;

use App\Models\AninoAnalysisRun;
use App\Models\Scan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class AninoRunManager
{
    public function active(Scan $scan): ?AninoAnalysisRun
    {
        $runs = $scan->aninoAnalysisRuns()
            ->whereIn('status', ['queued', 'running', 'running_with_errors'])
            ->latest('heartbeat_at')
            ->get();

        if ($runs->isEmpty()) {
            return null;
        }

        $cutoff = now()->subSeconds(
            max(120, (int) config('services.ollama.stale_after', 480))
        );
        $queueHasWork = $this->queueDepth() > 0;
        $active = $runs->first(fn (AninoAnalysisRun $run) => $run->heartbeat_at === null
            || $run->heartbeat_at->greaterThan($cutoff)
            || $queueHasWork
        );

        if ($active) {
            return $active;
        }

        if ($this->lockIsHeld($scan)) {
            Cache::lock($this->lockName($scan), 1)->forceRelease();
        }

        foreach ($runs as $run) {
            $run->update([
                'status' => 'failed',
                'phase' => 'stalled',
                'last_error' => 'The AI worker stopped responding. The run can be started again and completed reviewer results will be reused.',
                'completed_at' => now(),
            ]);

            Log::warning('ANINO stale analysis run recovered', [
                'scan_id' => $scan->id,
                'run_id' => $run->id,
            ]);
        }

        return null;
    }

    public function lockIsHeld(Scan $scan): bool
    {
        $lock = Cache::lock($this->lockName($scan), 1);

        if (! $lock->get()) {
            return true;
        }

        $lock->release();

        return false;
    }

    public function queueDepth(): int
    {
        return DB::table('jobs')
            ->where('queue', config('services.ollama.queue', 'ai-analysis'))
            ->count();
    }

    private function lockName(Scan $scan): string
    {
        return 'anino-analysis-run:'.$scan->id;
    }
}

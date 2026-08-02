<?php

namespace App\Http\Controllers\Web;

use App\Http\Controllers\Controller;
use App\Models\Finding;
use App\Services\Triage\FindingReport;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Full write-up for one finding: what the vulnerability is, why this code was
 * flagged, and the exact change to make — against the developer's own source.
 */
class FindingReportController extends Controller
{
    public function show(Finding $finding, FindingReport $report): Response
    {
        $finding->load(['scan.project', 'feedback', 'rule']);

        return Inertia::render('Findings/Report', $report->for($finding));
    }
}

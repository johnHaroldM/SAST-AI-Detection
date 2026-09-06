<?php

namespace App\Http\Controllers\Web;

use App\Http\Controllers\Controller;
use App\Models\Rule;
use Inertia\Inertia;
use Inertia\Response;

class RuleDashboardController extends Controller
{
    public function noisy(): Response
    {
        $rules = Rule::query()
            ->where('total_seen', '>=', 20)
            ->whereNotNull('recommended_action')
            ->orderByDesc('historical_fp_rate')
            ->get();

        return Inertia::render('Rules/Noisy', ['rules' => $rules]);
    }
}

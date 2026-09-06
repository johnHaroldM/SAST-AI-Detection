<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('anino_analysis_runs', function (Blueprint $table) {
            $table->json('candidate_finding_ids')->nullable()->after('current_finding_id');
            $table->unsignedInteger('processed_findings')->default(0)->after('total_findings');
            $table->unsignedInteger('failed_findings')->default(0)->after('reviewed_findings');
            $table->timestamp('phase_started_at')->nullable()->after('heartbeat_at');
        });
    }

    public function down(): void
    {
        Schema::table('anino_analysis_runs', function (Blueprint $table) {
            $table->dropColumn([
                'candidate_finding_ids',
                'processed_findings',
                'failed_findings',
                'phase_started_at',
            ]);
        });
    }
};

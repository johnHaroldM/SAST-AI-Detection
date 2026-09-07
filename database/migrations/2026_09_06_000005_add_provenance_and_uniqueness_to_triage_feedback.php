<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('triage_feedback', function (Blueprint $table) {
            $table->string('source', 32)->default('human')->after('corrected_label');
            $table->foreignId('source_ai_assessment_id')
                ->nullable()
                ->after('source')
                ->constrained('ai_assessments')
                ->nullOnDelete();
        });

        // Preserve the provenance of rows created by the pre-provenance
        // "Teach Rubix" flow. No existing row is deleted or relabelled.
        DB::table('triage_feedback')
            ->where('notes', 'like', 'AI training label from ATAKE/DEPENSA adjudicator%')
            ->orWhere('notes', 'like', 'AI_PROMOTED%')
            ->update(['source' => 'ai_pseudo']);

        Schema::table('triage_feedback', function (Blueprint $table) {
            // Finding::feedback() is a HasOne and final_label is the canonical
            // current decision, so there must be at most one current row.
            $table->unique('finding_id');
            $table->index(['source', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::table('triage_feedback', function (Blueprint $table) {
            $table->dropUnique(['finding_id']);
            $table->dropIndex(['source', 'created_at']);
            $table->dropConstrainedForeignId('source_ai_assessment_id');
            $table->dropColumn('source');
        });
    }
};

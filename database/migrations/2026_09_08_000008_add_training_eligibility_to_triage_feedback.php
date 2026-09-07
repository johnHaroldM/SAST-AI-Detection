<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('triage_feedback', function (Blueprint $table) {
            $table->boolean('training_eligible')
                ->default(true)
                ->after('source_ai_assessment_id');
            $table->text('training_exclusion_reason')
                ->nullable()
                ->after('training_eligible');

            $table->index(['source', 'training_eligible']);
        });
    }

    public function down(): void
    {
        Schema::table('triage_feedback', function (Blueprint $table) {
            $table->dropIndex(['source', 'training_eligible']);
            $table->dropColumn(['training_eligible', 'training_exclusion_reason']);
        });
    }
};

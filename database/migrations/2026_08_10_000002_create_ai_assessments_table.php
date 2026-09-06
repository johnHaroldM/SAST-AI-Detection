<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ai_assessments', function (Blueprint $table) {
            $table->id();

            $table->foreignId('finding_id')
                ->constrained()
                ->cascadeOnDelete();

            // atake | depensa | adjudicator
            $table->string('reviewer', 32);

            $table->string('model');
            $table->string('model_version')->nullable();

            // confirmed_tp | likely_tp | needs_validation | likely_fp | confirmed_fp
            // Deliberately distinct from findings.predicted_label /
            // findings.final_label — see project notes: AI never writes ground truth.
            $table->string('classification', 32);

            $table->decimal('confidence', 5, 4)->nullable();

            $table->boolean('attacker_controlled')->nullable();
            $table->boolean('sink_reachable')->nullable();
            $table->boolean('mitigation_detected')->nullable();

            $table->json('preconditions')->nullable();
            $table->json('supporting_evidence')->nullable();
            $table->json('contradicting_evidence')->nullable();
            $table->json('missing_evidence')->nullable();
            $table->json('remediation')->nullable();

            $table->text('reasoning_summary')->nullable();

            $table->string('prompt_version', 32)->default('v1');
            $table->string('context_hash', 64)->nullable();

            $table->json('usage')->nullable();
            $table->json('raw_response')->nullable();

            $table->timestamp('completed_at')->nullable();

            $table->timestamps();

            $table->index(['finding_id', 'reviewer']);
            $table->index(['classification', 'confidence']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ai_assessments');
    }
};

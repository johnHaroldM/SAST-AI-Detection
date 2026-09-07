<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ai_assessment_feedback', function (Blueprint $table) {
            $table->id();
            $table->foreignId('assessment_id')
                ->constrained('ai_assessments')
                ->cascadeOnDelete();
            $table->foreignId('user_id')
                ->constrained()
                ->cascadeOnDelete();

            $table->enum('verdict', [
                'correct',
                'incorrect',
                'partially_correct',
                'insufficient_context',
            ]);
            $table->enum('corrected_classification', [
                'confirmed_tp',
                'likely_tp',
                'needs_validation',
                'likely_fp',
                'confirmed_fp',
            ])->nullable();
            $table->json('reason_codes')->nullable();
            $table->text('notes')->nullable();
            $table->timestamp('reviewed_at');
            $table->timestamps();

            $table->unique(['assessment_id', 'user_id']);
            $table->index(['verdict', 'reviewed_at']);
            $table->index(['user_id', 'reviewed_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ai_assessment_feedback');
    }
};

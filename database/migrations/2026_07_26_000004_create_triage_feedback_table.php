<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('triage_feedback', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_id')->constrained()->cascadeOnDelete();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();

            $table->enum('original_prediction', ['true_positive', 'false_positive'])->nullable();
            $table->decimal('original_probability', 5, 4)->nullable();
            $table->enum('corrected_label', ['true_positive', 'false_positive']);
            $table->text('notes')->nullable();

            $table->timestamps();

            $table->index('finding_id');
            $table->index('created_at'); // used by TriageController::maybeTriggerRetraining
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('triage_feedback');
    }
};

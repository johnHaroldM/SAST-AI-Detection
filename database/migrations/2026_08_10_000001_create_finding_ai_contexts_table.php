<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('finding_ai_contexts', function (Blueprint $table) {
            $table->id();

            $table->foreignId('finding_id')
                ->unique()
                ->constrained()
                ->cascadeOnDelete();

            $table->string('source_commit')->nullable();

            // sha256 of the persisted context, for auditability and dedupe.
            $table->string('context_hash', 64);

            $table->json('metadata')->nullable();

            // The compact, size-capped evidence package sent to Ollama —
            // never the full repository. See FindingContextBuilder.
            $table->longText('context');

            $table->timestamps();

            $table->index('context_hash');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('finding_ai_contexts');
    }
};

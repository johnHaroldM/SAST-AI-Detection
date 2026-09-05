<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('model_states', function (Blueprint $table) {
            $table->id();
            $table->timestamp('trained_at');
            $table->unsignedInteger('sample_size');
            $table->decimal('precision', 5, 4);
            $table->decimal('recall', 5, 4);
            $table->decimal('f1_score', 5, 4);
            $table->json('confusion_matrix'); // {tp, fp, fn, tn}
            $table->timestamps();

            $table->index('trained_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('model_states');
    }
};

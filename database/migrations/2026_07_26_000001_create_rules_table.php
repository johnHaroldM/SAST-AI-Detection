<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('rules', function (Blueprint $table) {
            $table->id();
            $table->string('external_id')->unique(); // scanner's native rule ID
            $table->unsignedSmallInteger('cwe_id')->nullable();
            $table->text('description')->nullable();
            $table->unsignedInteger('total_seen')->default(0);
            $table->unsignedInteger('total_false_positive')->default(0);
            $table->decimal('historical_fp_rate', 5, 4)->default(0); // 0.0000 - 1.0000
            $table->enum('recommended_action', ['suppress', 'review_config'])->nullable();
            $table->timestamps();

            $table->index('historical_fp_rate');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('rules');
    }
};

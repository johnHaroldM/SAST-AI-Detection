<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('findings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();

            // Stores the scanner's native rule ID (e.g. "php.laravel.security.sql-injection"),
            // matched against rules.external_id — see note below on the Rule relationship.
            $table->string('rule_id');

            $table->unsignedSmallInteger('cwe_id')->nullable();
            $table->string('file_path');
            $table->unsignedInteger('line_number');
            $table->enum('severity', ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
            $table->text('message');
            $table->text('raw_snippet')->nullable();

            $table->json('feature_vector')->nullable();
            $table->decimal('tp_probability', 5, 4)->nullable();
            $table->enum('predicted_label', ['true_positive', 'false_positive'])->nullable();
            $table->enum('final_label', ['true_positive', 'false_positive'])->nullable();
            $table->enum('status', ['pending', 'triaged', 'suppressed', 'reported'])->default('pending');

            $table->timestamps();

            $table->index('rule_id');
            $table->index(['scan_id', 'status']);
            $table->index(['scan_id', 'predicted_label']);
            $table->index('tp_probability');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('findings');
    }
};

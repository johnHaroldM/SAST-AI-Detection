<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scans', function (Blueprint $table) {
            $table->id();
            $table->foreignId('project_id')->constrained()->cascadeOnDelete();
            $table->enum('source', ['semgrep', 'sonarqube', 'bandit', 'phpcs', 'sarif']);
            $table->char('commit_sha', 40);
            $table->string('branch');
            $table->string('raw_report_path');
            $table->enum('status', ['uploaded', 'parsing', 'scoring', 'complete', 'failed'])
                ->default('uploaded');
            $table->unsignedInteger('total_findings')->default(0);
            $table->unsignedInteger('suppressed_count')->default(0);
            $table->timestamps();

            $table->index(['project_id', 'created_at']);
            $table->index('commit_sha');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scans');
    }
};

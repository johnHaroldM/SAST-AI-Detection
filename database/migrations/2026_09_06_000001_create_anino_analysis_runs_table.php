<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('anino_analysis_runs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('status', 32)->default('queued');
            $table->string('phase', 32)->nullable();
            $table->unsignedBigInteger('current_finding_id')->nullable();
            $table->unsignedInteger('total_findings')->default(0);
            $table->unsignedInteger('reviewed_findings')->default(0);
            $table->text('last_error')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('heartbeat_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->timestamps();

            $table->index(['scan_id', 'status']);
            $table->index('heartbeat_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('anino_analysis_runs');
    }
};

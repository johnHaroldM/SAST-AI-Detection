<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Minimal stand-in so scans.project_id has a valid FK target.
 * vcs_repo_slug / vcs_access_token are read by PostPrCommentsJob.
 * Expand this once real org/team ownership is designed.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('projects', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('vcs_repo_slug')->nullable();   // e.g. "org/repo"
            $table->text('vcs_access_token')->nullable();  // stored encrypted via $casts
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('projects');
    }
};

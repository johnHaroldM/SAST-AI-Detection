<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Lets a project say where its source can be obtained.
 *
 * vcs_host  - which allowlisted forge to clone from (github.com by default)
 * source_path - an on-disk working copy, for local development only; a hosted
 *               deployment leaves this null and always clones
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table) {
            $table->string('vcs_host')->nullable()->after('vcs_repo_slug');
            $table->string('source_path')->nullable()->after('vcs_access_token');
        });
    }

    public function down(): void
    {
        Schema::table('projects', function (Blueprint $table) {
            $table->dropColumn(['vcs_host', 'source_path']);
        });
    }
};

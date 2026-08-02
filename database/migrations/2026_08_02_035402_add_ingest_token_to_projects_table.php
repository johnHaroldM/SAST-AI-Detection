<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Per-project upload credentials for CLI and CI ingestion.
 *
 * Scoped to a single project rather than to a user account, so a token
 * leaked from a build agent can only push reports for that one project —
 * it cannot read findings, browse other projects, or act as its creator.
 *
 * Only the hash is stored; the plaintext is shown once at creation.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table) {
            $table->string('ingest_token_hash', 64)->nullable()->unique()->after('source_path');
            $table->string('ingest_token_hint', 12)->nullable()->after('ingest_token_hash');
            $table->timestamp('ingest_token_created_at')->nullable()->after('ingest_token_hint');
            $table->timestamp('ingest_token_last_used_at')->nullable()->after('ingest_token_created_at');
        });
    }

    public function down(): void
    {
        Schema::table('projects', function (Blueprint $table) {
            $table->dropColumn([
                'ingest_token_hash',
                'ingest_token_hint',
                'ingest_token_created_at',
                'ingest_token_last_used_at',
            ]);
        });
    }
};

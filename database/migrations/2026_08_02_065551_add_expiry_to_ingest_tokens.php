<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Expiry for upload credentials.
 *
 * A token pasted into a CI configuration outlives the person who created it,
 * the machine it was created for, and often the project itself. Revocation
 * only helps when somebody remembers to revoke; an expiry date turns
 * forgetting into the safe default.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table) {
            $table->timestamp('ingest_token_expires_at')->nullable()->after('ingest_token_last_used_at');
        });
    }

    public function down(): void
    {
        Schema::table('projects', function (Blueprint $table) {
            $table->dropColumn('ingest_token_expires_at');
        });
    }
};

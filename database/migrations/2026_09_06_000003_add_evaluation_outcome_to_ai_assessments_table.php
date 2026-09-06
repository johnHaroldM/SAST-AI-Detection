<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ai_assessments', function (Blueprint $table) {
            $table->string('evaluation_outcome', 32)->nullable()->after('classification');
            $table->index(['reviewer', 'evaluation_outcome']);
        });
    }

    public function down(): void
    {
        Schema::table('ai_assessments', function (Blueprint $table) {
            $table->dropIndex(['reviewer', 'evaluation_outcome']);
            $table->dropColumn('evaluation_outcome');
        });
    }
};

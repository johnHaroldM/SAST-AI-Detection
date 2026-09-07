<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('model_states', function (Blueprint $table) {
            $table->string('deployment_status', 32)
                ->default('legacy')
                ->after('confusion_matrix')
                ->index();
            $table->decimal('decision_threshold', 5, 4)
                ->nullable()
                ->after('deployment_status');
            $table->string('model_path')
                ->nullable()
                ->after('decision_threshold');
            $table->json('evaluation_metadata')
                ->nullable()
                ->after('model_path');
        });
    }

    public function down(): void
    {
        Schema::table('model_states', function (Blueprint $table) {
            $table->dropIndex(['deployment_status']);
            $table->dropColumn([
                'deployment_status',
                'decision_threshold',
                'model_path',
                'evaluation_metadata',
            ]);
        });
    }
};

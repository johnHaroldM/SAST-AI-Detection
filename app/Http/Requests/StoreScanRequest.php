<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * Shared validation for scan uploads, used by both the JSON API
 * (ScanController) and the Inertia dashboard (ScanDashboardController) so
 * the two entry points can never drift apart on what they accept.
 */
class StoreScanRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user() !== null;
    }

    /**
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'project_id' => ['required', 'integer', 'exists:projects,id'],
            'source' => ['required', Rule::in(['semgrep', 'sonarqube', 'bandit', 'phpcs', 'sarif'])],
            'commit_sha' => ['required', 'string', 'size:40', 'regex:/^[0-9a-f]{40}$/i'],
            'branch' => ['required', 'string', 'max:255'],
            'report' => ['required', 'file', 'mimetypes:application/json,text/plain', 'max:51200'], // 50MB cap
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'commit_sha.regex' => 'The commit SHA must be a full 40-character hex hash.',
            'report.mimetypes' => 'The report must be a JSON or SARIF file.',
        ];
    }
}

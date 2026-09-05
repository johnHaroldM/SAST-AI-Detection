<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Validator;

/**
 * Registering a project from the UI, so pointing the scanner at code no
 * longer requires dropping into tinker.
 */
class StoreProjectRequest extends FormRequest
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
            'name' => ['required', 'string', 'max:255'],
            'source_path' => ['nullable', 'string', 'max:1024'],
            'vcs_repo_slug' => ['nullable', 'string', 'max:255', 'regex:/^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*$/'],
        ];
    }

    /**
     * A path that does not exist produces a project that silently never
     * scans, so it is worth catching at the point of entry rather than
     * leaving the user to wonder why nothing happens.
     *
     * @return list<callable(Validator): void>
     */
    public function after(): array
    {
        return [
            function (Validator $validator): void {
                $path = $this->string('source_path')->trim()->toString();

                if ($path === '') {
                    return;
                }

                if (! is_dir($path)) {
                    $validator->errors()->add('source_path', 'That directory does not exist on this machine.');

                    return;
                }

                if (! is_readable($path)) {
                    $validator->errors()->add('source_path', 'That directory exists but cannot be read by the web process.');
                }
            },
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'vcs_repo_slug.regex' => 'Use the owner/repository form, for example acme/checkout-api.',
        ];
    }
}

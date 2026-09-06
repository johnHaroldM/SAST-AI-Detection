<?php

namespace App\Services\Triage;

use App\Models\Finding;

/**
 * Turns a finding's own line of code into a concrete before/after.
 *
 * Generic advice ("use bindings") is easy to nod at and hard to act on. This
 * rewrites the actual statement that was flagged, keeping the developer's own
 * variable names, so the change required is obvious.
 *
 * These are *suggestions*, not patches. The rewrites are syntactic and cannot
 * know the surrounding contract, so the report presents them as the shape of
 * the fix rather than something to paste blindly.
 */
class SuggestedFix
{
    /**
     * @return array{before:string, after:string, note:string}|null
     */
    public function for(Finding $finding): ?array
    {
        $line = trim((string) $finding->raw_snippet);

        if ($line === '') {
            return null;
        }

        return match ($finding->cwe_id) {
            22 => $this->pathTraversal($line),
            89 => $this->sqlInjection($line),
            78 => $this->commandInjection($line),
            502 => $this->deserialization($line),
            915 => $this->massAssignment($line),
            327 => $this->weakHashing($line),
            798 => $this->hardcodedSecret($line),
            79 => $this->unescapedOutput($line),
            default => null,
        };
    }

    /**
     * @return array{before:string, after:string, note:string}
     */
    private function pathTraversal(string $line): array
    {
        // Rewrite the first variable used as a path so it is contained.
        $after = preg_replace_callback(
            '/\b(file_put_contents|file_get_contents|fopen|unlink|readfile|mkdir|rmdir|copy|rename)\s*\(\s*(\$[A-Za-z_]\w*)/',
            fn (array $m) => $m[1].'($safePath',
            $line,
            1
        ) ?? $line;

        $variable = $this->firstVariable($line) ?? '$path';

        return [
            'before' => $line,
            'after' => "\$base = realpath(storage_path('uploads'));\n"
                ."\$safePath = realpath(\$base.DIRECTORY_SEPARATOR.basename({$variable}));\n\n"
                ."// Refuse anything that escaped the intended directory.\n"
                ."abort_unless(\$safePath && str_starts_with(\$safePath, \$base), 403);\n\n"
                .$after,
            'note' => "basename() strips any ../ segments, and the realpath() prefix check catches symlinks that would otherwise escape. Better still: never store the user's filename — generate one with Str::uuid() and keep the original only as a display label.",
        ];
    }

    /**
     * @return array{before:string, after:string, note:string}
     */
    private function sqlInjection(string $line): array
    {
        $after = preg_replace('/\$\w+(->\w+)*/', '?', $line) ?? $line;
        $variables = $this->allVariables($line);

        return [
            'before' => $line,
            'after' => rtrim($after, ';').', ['.implode(', ', $variables ?: ['$value']).']);',
            'note' => 'Each interpolated value becomes a ? placeholder and moves into the bindings array, so the driver never parses it as SQL. Table and column names cannot be bound — if one must be dynamic, check it against a hardcoded allowlist first.',
        ];
    }

    /**
     * @return array{before:string, after:string, note:string}
     */
    private function commandInjection(string $line): array
    {
        $variable = $this->firstVariable($line) ?? '$argument';

        return [
            'before' => $line,
            'after' => "use Symfony\\Component\\Process\\Process;\n\n"
                ."\$process = new Process(['convert', {$variable}, 'out.png']);\n"
                .'$process->mustRun();',
            'note' => 'Passing arguments as an array means no shell is spawned, so metacharacters such as ; | && $() have no special meaning. If you genuinely need a shell string, wrap every variable in escapeshellarg().',
        ];
    }

    /**
     * @return array{before:string, after:string, note:string}
     */
    private function deserialization(string $line): array
    {
        return [
            'before' => $line,
            'after' => str_replace(
                'unserialize(',
                'json_decode(',
                rtrim($line, ';')
            ).', true, flags: JSON_THROW_ON_ERROR);',
            'note' => 'json_decode() produces only arrays and scalars, so there are no object constructors or magic methods for a crafted payload to reach. Changing the format means any already-stored serialized values need migrating.',
        ];
    }

    /**
     * @return array{before:string, after:string, note:string}
     */
    private function massAssignment(string $line): array
    {
        return [
            'before' => $line,
            'after' => str_replace(
                ['$request->all()', 'request()->all()'],
                "\$request->validate([\n    'name' => ['required', 'string', 'max:255'],\n    // ...only the fields a user may set\n])",
                $line
            ),
            'note' => 'Passing the validated subset means an unexpected field simply never reaches the model. Also declare $fillable on the model itself, so a second call site cannot reintroduce the same hole.',
        ];
    }

    /**
     * @return array{before:string, after:string, note:string}
     */
    private function weakHashing(string $line): array
    {
        return [
            'before' => $line,
            'after' => preg_replace('/\b(md5|sha1)\s*\(/', 'Hash::make(', $line) ?? $line,
            'note' => 'Only change this if the value is security-relevant — a password, token or signature. For a cache key or filename md5 is fine and Hash::make() would be actively wrong, since it salts and never produces a stable key.',
        ];
    }

    /**
     * @return array{before:string, after:string, note:string}
     */
    private function hardcodedSecret(string $line): array
    {
        $variable = $this->firstVariable($line) ?? '$secret';

        return [
            'before' => $line,
            'after' => "// config/services.php\n'api_key' => env('SERVICE_API_KEY'),\n\n"
                ."// .env  (never committed)\nSERVICE_API_KEY=…\n\n"
                ."// here\n{$variable} = config('services.api_key');",
            'note' => 'Read through config() rather than env() directly, so the value survives config caching. If this secret was ever committed, rotate it — removing the line does not remove it from git history.',
        ];
    }

    /**
     * @return array{before:string, after:string, note:string}
     */
    private function unescapedOutput(string $line): array
    {
        return [
            'before' => $line,
            'after' => preg_replace('/\becho\s+(\$[^;]+);/', 'echo e($1);', $line) ?? $line,
            'note' => 'In a Blade template use {{ $value }}, which escapes by default, instead of {!! $value !!}. Escaping is only needed for HTML output — it would corrupt a JSON response or a binary download.',
        ];
    }

    private function firstVariable(string $line): ?string
    {
        return preg_match('/\$[A-Za-z_]\w*/', $line, $m) === 1 ? $m[0] : null;
    }

    /**
     * @return list<string>
     */
    private function allVariables(string $line): array
    {
        preg_match_all('/\$[A-Za-z_]\w*(?:->\w+)*/', $line, $matches);

        return array_values(array_unique($matches[0]));
    }
}

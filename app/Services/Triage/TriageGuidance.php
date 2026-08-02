<?php

namespace App\Services\Triage;

/**
 * Everything a reviewer needs at the moment of judging a finding: what
 * separates a true positive from a false positive, what an attacker actually
 * gains, and how the code should be written instead.
 *
 * Label quality is the ceiling on model quality — inconsistent labels teach
 * the classifier noise — and a reviewer working a long queue drifts without
 * the criteria in front of them. Keyed on CWE rather than rule id so it also
 * covers findings ingested from external scanners whose rule identifiers this
 * app has never seen.
 *
 * @phpstan-type Advice array{
 *   title: string,
 *   truePositive: string,
 *   falsePositive: string,
 *   risk: string,
 *   fix: string,
 *   vulnerable: string,
 *   secure: string,
 *   reference: string
 * }
 */
class TriageGuidance
{
    /** @var array<int, Advice> */
    private const BY_CWE = [
        89 => [
            'title' => 'SQL injection',
            'truePositive' => 'Request data reaches the query string without binding — concatenation or interpolation of anything derived from input.',
            'falsePositive' => 'The dynamic part is a bound parameter, a hardcoded constant, a column name from a fixed allowlist, or a value the application itself generated.',
            'risk' => 'An attacker rewrites the query: reading every row in the database, bypassing authentication, or in some configurations writing files to disk.',
            'fix' => 'Pass values as bindings so the driver sends them separately from the SQL text. Where a table or column name really must be dynamic, validate it against a hardcoded allowlist — identifiers cannot be bound.',
            'vulnerable' => 'DB::select("SELECT * FROM users WHERE email = \'" . $request->email . "\'");',
            'secure' => 'DB::select("SELECT * FROM users WHERE email = ?", [$request->email]);',
            'reference' => 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
        ],
        78 => [
            'title' => 'Command injection',
            'truePositive' => 'Any part of the command string comes from a request, a database row, or a file the user controls.',
            'falsePositive' => 'The argument is escaped with escapeshellarg(), or the whole command is assembled from constants.',
            'risk' => 'Arbitrary code execution as the web server user. Shell metacharacters such as ; | && $() let an attacker append their own commands.',
            'fix' => 'Prefer an array-argument process runner, which never invokes a shell at all. If you must build a string, wrap every interpolated value in escapeshellarg().',
            'vulnerable' => 'shell_exec("convert " . $request->file . " out.png");',
            'secure' => 'new Symfony\\Component\\Process\\Process(["convert", $request->file, "out.png"]);',
            'reference' => 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
        ],
        502 => [
            'title' => 'Unsafe deserialization',
            'truePositive' => 'unserialize() receives data that crossed a trust boundary — a request, cookie, or uploaded file.',
            'falsePositive' => 'The payload came from the application itself, e.g. a cache entry or a value it serialized moments earlier.',
            'risk' => 'Object injection. A crafted payload instantiates arbitrary classes and triggers their magic methods (__wakeup, __destruct), which can chain into code execution or file deletion.',
            'fix' => 'Use a data format that does not instantiate objects. json_decode() returns only arrays and scalars, so there is no gadget chain to exploit.',
            'vulnerable' => '$data = unserialize($request->input("payload"));',
            'secure' => '$data = json_decode($request->input("payload"), true, flags: JSON_THROW_ON_ERROR);',
            'reference' => 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
        ],
        22 => [
            'title' => 'Path traversal',
            'truePositive' => 'A filename or path segment derives from user input with no basename()/realpath() containment.',
            'falsePositive' => 'The path is built from a config value, a fixed directory plus a generated id, or is validated against an allowlist.',
            'risk' => 'A ../ sequence escapes the intended directory, giving an attacker read, write or delete access to files elsewhere on disk — including .env, source code, or a web-served directory.',
            'fix' => 'Never build a path from a user-supplied name. Generate the stored name yourself, or at minimum apply basename() and then verify the resolved realpath() still sits inside the intended directory.',
            'vulnerable' => '$path = storage_path("uploads/" . $request->input("fileName"));',
            'secure' => '$path = storage_path("uploads/" . Str::uuid() . "." . $file->extension());',
            'reference' => 'https://owasp.org/www-community/attacks/Path_Traversal',
        ],
        79 => [
            'title' => 'Cross-site scripting',
            'truePositive' => 'User-controlled text is rendered into HTML without escaping.',
            'falsePositive' => 'The value is escaped elsewhere, is not user-controlled, or the output is JSON/plain text rather than HTML.',
            'risk' => 'Script runs in another user\'s browser under your origin — session theft, actions performed as that user, or credential harvesting via an injected form.',
            'fix' => 'Use Blade\'s {{ }}, which escapes by default. Reserve {!! !!} for HTML you generated yourself, and sanitise with a library such as HTMLPurifier if users must supply markup.',
            'vulnerable' => '{!! $comment->body !!}',
            'secure' => '{{ $comment->body }}',
            'reference' => 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        ],
        915 => [
            'title' => 'Mass assignment',
            'truePositive' => 'The model has no $fillable/$guarded protection, so a crafted request could set a sensitive column such as is_admin.',
            'falsePositive' => 'The model defines $fillable and the sensitive columns are excluded — which is the norm in most Laravel codebases.',
            'risk' => 'Privilege escalation. An attacker adds is_admin=1 or user_id=<someone else> to the request body and the model writes it without complaint.',
            'fix' => 'Declare $fillable on the model with only the columns a user may set, and pass the validated subset rather than the whole request.',
            'vulnerable' => 'User::create($request->all());',
            'secure' => 'User::create($request->only(["name", "email"]));',
            'reference' => 'https://laravel.com/docs/eloquent#mass-assignment',
        ],
        327 => [
            'title' => 'Weak hashing',
            'truePositive' => 'md5/sha1 protects something security-relevant: a password, token, or signature.',
            'falsePositive' => 'The hash is a cache key, ETag, checksum, or shard selector, where collision resistance does not matter.',
            'risk' => 'md5 and sha1 are fast and collision-prone. Password hashes fall to commodity GPU cracking, and signatures can be forged via collision.',
            'fix' => 'For passwords use bcrypt/argon2 via Hash::make(), which is deliberately slow and salted. For signatures use hash_hmac with sha256 and compare with hash_equals().',
            'vulnerable' => '$stored = md5($request->password);',
            'secure' => '$stored = Hash::make($request->password);',
            'reference' => 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
        ],
        798 => [
            'title' => 'Hardcoded credential',
            'truePositive' => 'A real, usable secret is committed in source.',
            'falsePositive' => 'A placeholder, a test fixture, a public key, or a default that env() overrides in every real environment.',
            'risk' => 'Anyone with repository access holds the credential — including past employees and anyone who sees a fork, a backup, or the git history. Rotation is the only remedy once it leaks.',
            'fix' => 'Move the value into .env, read it through config(), and keep .env out of version control. If it was ever committed, rotate it — deleting the line does not remove it from history.',
            'vulnerable' => '$apiKey = "sk-live-9f83nfu2b8vd0193ndkq";',
            'secure' => '$apiKey = config("services.stripe.key"); // .env: STRIPE_KEY=…',
            'reference' => 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
        ],
    ];

    /** @var Advice */
    private const FALLBACK = [
        'title' => 'Security finding',
        'truePositive' => 'Untrusted input reaches the dangerous operation and nothing along the path neutralises it.',
        'falsePositive' => 'The value is trusted, validated, or escaped before it gets here — or the code path is unreachable.',
        'risk' => 'Depends on the sink. Trace what an attacker controls and what the operation can do with it.',
        'fix' => 'Establish where the value enters the system, then validate or encode it for the context it is used in.',
        'vulnerable' => '',
        'secure' => '',
        'reference' => 'https://cwe.mitre.org/',
    ];

    /**
     * @return Advice
     */
    public function for(?int $cweId): array
    {
        return self::BY_CWE[$cweId] ?? self::FALLBACK;
    }

    /**
     * Guidance for every CWE present in a set, keyed by CWE id, so a page can
     * ship exactly the entries its findings need.
     *
     * @param  iterable<int|null>  $cweIds
     * @return array<int|string, Advice>
     */
    public function forMany(iterable $cweIds): array
    {
        $guidance = [];

        foreach ($cweIds as $cweId) {
            $guidance[$cweId ?? 'unknown'] = $this->for($cweId);
        }

        return $guidance;
    }

    /**
     * Every CWE this service has specific advice for.
     *
     * @return list<int>
     */
    public function knownCwes(): array
    {
        return array_keys(self::BY_CWE);
    }
}

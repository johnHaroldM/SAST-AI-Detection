<?php

namespace App\Models;

use Database\Factories\ProjectFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Str;

class Project extends Model
{
    /** @use HasFactory<ProjectFactory> */
    use HasFactory;

    protected $fillable = [
        'name',
        'vcs_repo_slug',
        'vcs_host',
        'vcs_access_token',
        'source_path',
    ];

    /**
     * The VCS token is encrypted at rest — PostPrCommentsJob reads it back
     * as plaintext through this cast rather than calling decrypt() itself.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'vcs_access_token' => 'encrypted',
        'ingest_token_created_at' => 'datetime',
        'ingest_token_last_used_at' => 'datetime',
        'ingest_token_expires_at' => 'datetime',
    ];

    /**
     * @var list<string>
     */
    protected $hidden = [
        'vcs_access_token',
        'ingest_token_hash',
    ];

    /**
     * Issue a fresh upload credential, returning the plaintext exactly once.
     *
     * Only the SHA-256 hash is persisted, so a database dump does not hand
     * over working upload credentials. Issuing a new token invalidates the
     * previous one — there is deliberately no way to have two live at once,
     * which keeps revocation unambiguous.
     */
    public function issueIngestToken(?int $lifetimeDays = null): string
    {
        $plaintext = 'sast_'.Str::random(48);
        $lifetimeDays ??= (int) config('sast.ingest.token_lifetime_days', 90);

        $this->forceFill([
            'ingest_token_hash' => hash('sha256', $plaintext),
            // Enough to recognise which token is configured where, not enough
            // to reconstruct it.
            'ingest_token_hint' => Str::substr($plaintext, 0, 10),
            'ingest_token_created_at' => now(),
            'ingest_token_last_used_at' => null,
            // Revocation only helps when somebody remembers. Expiry makes
            // forgetting the safe outcome. 0 means no expiry, for anyone who
            // deliberately wants a long-lived credential.
            'ingest_token_expires_at' => $lifetimeDays > 0 ? now()->addDays($lifetimeDays) : null,
        ])->save();

        return $plaintext;
    }

    public function ingestTokenHasExpired(): bool
    {
        return $this->ingest_token_expires_at !== null
            && $this->ingest_token_expires_at->isPast();
    }

    public function revokeIngestToken(): void
    {
        $this->forceFill([
            'ingest_token_hash' => null,
            'ingest_token_hint' => null,
            'ingest_token_created_at' => null,
            'ingest_token_last_used_at' => null,
        ])->save();
    }

    public function hasIngestToken(): bool
    {
        return filled($this->ingest_token_hash);
    }

    /**
     * Resolve a presented token to its project in constant time.
     *
     * The lookup is by hash, so a timing difference cannot reveal whether a
     * given prefix exists.
     */
    public static function findByIngestToken(string $plaintext): ?self
    {
        if (trim($plaintext) === '') {
            return null;
        }

        $project = static::query()
            ->where('ingest_token_hash', hash('sha256', trim($plaintext)))
            ->first();

        // An expired token is indistinguishable from a wrong one to the
        // caller — the endpoint returns the same 401 either way, so a probe
        // learns nothing about whether a credential once existed.
        return $project?->ingestTokenHasExpired() ? null : $project;
    }

    /**
     * @return HasMany<Scan, $this>
     */
    public function scans(): HasMany
    {
        return $this->hasMany(Scan::class);
    }
}

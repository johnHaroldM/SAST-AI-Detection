<?php

namespace App\Services\Scanner;

use App\Services\ScannerReportParsers\NormalizedFindingDTO;
use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Parser;
use PhpParser\ParserFactory;

/**
 * Walks a project directory and applies every registered SecurityRule.
 *
 * One parse and one traversal per file, with each node offered to all rules,
 * so adding a rule costs nothing extra in I/O. Produces the same
 * NormalizedFindingDTO the external report parsers emit, which is what lets
 * scan results flow through the untouched ingestion pipeline.
 */
class ProjectScanner
{
    private Parser $parser;

    /** @var list<SecurityRule> */
    private array $rules;

    /** @var list<string> */
    private array $skippedFiles = [];

    private int $filesScanned = 0;

    /** @var list<string> */
    private array $excludedDirectories;

    private int $maxFileBytes;

    /**
     * Configuration is injected rather than read from the framework, so this
     * class depends on nothing but nikic/php-parser. That is what makes the
     * analyser distributable on its own — as a phar, a standalone package, or
     * inside a CI container — without dragging the whole application along.
     *
     * @param  iterable<SecurityRule>  $rules
     * @param  list<string>  $excludedDirectories
     */
    public function __construct(
        iterable $rules,
        array $excludedDirectories = [],
        int $maxFileBytes = 1_000_000,
    ) {
        $this->parser = (new ParserFactory)->createForNewestSupportedVersion();
        $this->rules = is_array($rules) ? array_values($rules) : iterator_to_array($rules, false);
        $this->excludedDirectories = array_map('strtolower', $excludedDirectories);
        $this->maxFileBytes = $maxFileBytes;
    }

    /**
     * @return list<NormalizedFindingDTO>
     */
    public function scan(string $projectRoot): array
    {
        $this->filesScanned = 0;
        $this->skippedFiles = [];

        $root = rtrim($projectRoot, '/\\');

        if (! is_dir($root)) {
            return [];
        }

        $findings = [];

        foreach ($this->phpFiles($root) as $absolutePath) {
            $relative = ltrim(str_replace('\\', '/', substr($absolutePath, strlen($root))), '/');

            foreach ($this->scanFile($absolutePath, $relative) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    public function filesScanned(): int
    {
        return $this->filesScanned;
    }

    /**
     * @return list<string>
     */
    public function skippedFiles(): array
    {
        return $this->skippedFiles;
    }

    /**
     * @return list<NormalizedFindingDTO>
     */
    private function scanFile(string $absolutePath, string $relativePath): array
    {
        $code = @file_get_contents($absolutePath);

        if ($code === false) {
            $this->skippedFiles[] = $relativePath;

            return [];
        }

        try {
            $ast = $this->parser->parse($code);
        } catch (Error) {
            // Unparseable (older syntax, a template fragment) — record it so
            // coverage is honest rather than silently smaller than reported.
            $this->skippedFiles[] = $relativePath;

            return [];
        }

        if ($ast === null) {
            $this->skippedFiles[] = $relativePath;

            return [];
        }

        $this->filesScanned++;

        $lines = explode("\n", $code);
        $collected = [];

        $visitor = new class($this->rules) extends NodeVisitorAbstract
        {
            /** @var list<array{SecurityRule, RuleMatch}> */
            public array $hits = [];

            /** @param list<SecurityRule> $rules */
            public function __construct(private array $rules) {}

            public function enterNode(Node $node): ?Node
            {
                foreach ($this->rules as $rule) {
                    foreach ($rule->inspect($node) as $match) {
                        $this->hits[] = [$rule, $match];
                    }
                }

                return null;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        foreach ($visitor->hits as [$rule, $match]) {
            $collected[] = new NormalizedFindingDTO(
                ruleId: $rule->id(),
                cweId: $rule->cweId(),
                filePath: $relativePath,
                lineNumber: max(1, $match->line),
                severity: $rule->severity(),
                message: $match->message ?? $rule->description(),
                snippet: $match->snippet ?? $this->snippetAt($lines, $match->line),
            );
        }

        return $collected;
    }

    /**
     * @param  list<string>  $lines
     */
    private function snippetAt(array $lines, int $line): ?string
    {
        $text = $lines[$line - 1] ?? null;

        return $text === null ? null : trim($text);
    }

    /**
     * @return \Generator<string>
     */
    private function phpFiles(string $root): \Generator
    {
        $excluded = $this->excludedDirectories;
        $maxBytes = $this->maxFileBytes;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                function (\SplFileInfo $current) use ($excluded): bool {
                    if (! $current->isDir()) {
                        return true;
                    }

                    return ! in_array(strtolower($current->getFilename()), $excluded, true);
                }
            ),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if (! $file->isFile() || strtolower($file->getExtension()) !== 'php') {
                continue;
            }

            // Generated or minified files blow up parse time for no benefit.
            if ($file->getSize() > $maxBytes) {
                $this->skippedFiles[] = $file->getFilename();

                continue;
            }

            yield $file->getPathname();
        }
    }
}

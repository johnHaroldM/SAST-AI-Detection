<?php

namespace App\Services;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Parser;
use PhpParser\ParserFactory;

/**
 * Extracts static-analysis-relevant features from source code around a
 * given finding's file/line using the PHP AST (nikic/php-parser).
 *
 * These features feed directly into the Feature Vector consumed by
 * RubixTriageService::predict().
 */
class AstFeatureExtractor
{
    private Parser $parser;

    // Functions we treat as "sanitizers" for the purpose of the FP heuristic.
    // In production this list would be config-driven and CWE-specific
    // (e.g. htmlspecialchars for XSS, PDO::quote for SQLi, etc.).
    public const SANITIZER_FUNCTIONS = [
        'htmlspecialchars', 'htmlentities', 'strip_tags',
        'filter_var', 'escapeshellarg', 'escapeshellcmd',
        'addslashes', 'mysqli_real_escape_string',
        'DB::raw', // intentionally flagged elsewhere as risky, kept out of this list normally
    ];

    public const SANITIZER_METHODS = [
        'quote', 'prepare', 'bind', 'bindValue', 'bindParam',
        'e', // Blade's {{ }} helper compiles to htmlspecialchars via e()
    ];

    public function __construct()
    {
        $this->parser = (new ParserFactory)->createForNewestSupportedVersion();
    }

    /**
     * Build the AST-derived subset of the feature vector for a single finding.
     *
     * @return array{
     *   cyclomatic_complexity:int,
     *   has_sanitizer_in_ast:int,
     *   line_depth_in_function:int,
     *   is_test_file:int,
     *   file_extension:string
     * }
     */
    public function extract(string $absoluteFilePath, int $lineNumber): array
    {
        $defaults = [
            'cyclomatic_complexity' => 1,
            'has_sanitizer_in_ast' => 0,
            'line_depth_in_function' => 0,
            'is_test_file' => $this->isTestFile($absoluteFilePath) ? 1 : 0,
            'file_extension' => $this->normalizedExtension($absoluteFilePath),
        ];

        if (! is_readable($absoluteFilePath)) {
            return $defaults;
        }

        $code = file_get_contents($absoluteFilePath);

        if ($code === false) {
            return $defaults;
        }

        try {
            $ast = $this->parser->parse($code);
        } catch (Error) {
            // Unparseable file (e.g. pure Blade template) — fall back to defaults.
            return $defaults;
        }

        if ($ast === null) {
            return $defaults;
        }

        $enclosingFunction = $this->findEnclosingFunction($ast, $lineNumber);

        if ($enclosingFunction === null) {
            return $defaults;
        }

        return [
            'cyclomatic_complexity' => $this->cyclomaticComplexity($enclosingFunction),
            'has_sanitizer_in_ast' => $this->containsSanitizerCall($enclosingFunction) ? 1 : 0,
            'line_depth_in_function' => $lineNumber - $enclosingFunction->getStartLine(),
            'is_test_file' => $defaults['is_test_file'],
            'file_extension' => $defaults['file_extension'],
        ];
    }

    /**
     * Walk the AST to find the function/method/closure body that contains
     * the target line number. Returns the tightest enclosing scope.
     *
     * @param  array<int, Node>  $ast
     */
    private function findEnclosingFunction(array $ast, int $lineNumber): ?Node
    {
        $visitor = new class($lineNumber) extends NodeVisitorAbstract
        {
            public ?Node $match = null;

            public function __construct(private int $lineNumber) {}

            public function enterNode(Node $node): ?Node
            {
                $isScope = $node instanceof Node\Stmt\ClassMethod
                    || $node instanceof Node\Stmt\Function_
                    || $node instanceof Node\Expr\Closure
                    || $node instanceof Node\Expr\ArrowFunction;

                if ($isScope
                    && $node->getStartLine() <= $this->lineNumber
                    && $node->getEndLine() >= $this->lineNumber
                ) {
                    // Prefer the innermost (most recently matched, still-enclosing) scope.
                    $this->match = $node;
                }

                return null;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $visitor->match;
    }

    /**
     * McCabe cyclomatic complexity: 1 + count of decision points
     * (if/elseif/for/foreach/while/case/catch/&&/||/?:) within the node.
     */
    private function cyclomaticComplexity(Node $functionNode): int
    {
        $complexity = 1;

        $visitor = new class extends NodeVisitorAbstract
        {
            public int $count = 0;

            public function enterNode(Node $node): ?Node
            {
                if ($node instanceof Node\Stmt\If_
                    || $node instanceof Node\Stmt\ElseIf_
                    || $node instanceof Node\Stmt\For_
                    || $node instanceof Node\Stmt\Foreach_
                    || $node instanceof Node\Stmt\While_
                    || $node instanceof Node\Stmt\Do_
                    || $node instanceof Node\Stmt\Case_
                    || $node instanceof Node\Stmt\Catch_
                    || $node instanceof Node\Expr\BinaryOp\BooleanAnd
                    || $node instanceof Node\Expr\BinaryOp\BooleanOr
                    || $node instanceof Node\Expr\Ternary
                ) {
                    $this->count++;
                }

                return null;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse([$functionNode]);

        return $complexity + $visitor->count;
    }

    /**
     * Detect whether any known sanitizer function/method is called
     * anywhere within the enclosing function scope.
     */
    private function containsSanitizerCall(Node $functionNode): bool
    {
        $visitor = new class extends NodeVisitorAbstract
        {
            public bool $found = false;

            public function enterNode(Node $node): ?Node
            {
                if ($node instanceof Node\Expr\FuncCall
                    && $node->name instanceof Node\Name
                ) {
                    $name = strtolower($node->name->toString());
                    if (in_array($name, array_map('strtolower', AstFeatureExtractor::SANITIZER_FUNCTIONS), true)) {
                        $this->found = true;
                    }
                }

                if ($node instanceof Node\Expr\MethodCall
                    && $node->name instanceof Node\Identifier
                ) {
                    $name = $node->name->toString();
                    if (in_array($name, AstFeatureExtractor::SANITIZER_METHODS, true)) {
                        $this->found = true;
                    }
                }

                return null;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse([$functionNode]);

        return $visitor->found;
    }

    private function isTestFile(string $path): bool
    {
        return (bool) preg_match('#/(tests?|spec)/#i', $path)
            || (bool) preg_match('/(Test|Spec)\.php$/', $path);
    }

    private function normalizedExtension(string $path): string
    {
        if (str_ends_with($path, '.blade.php')) {
            return 'blade.php';
        }

        return pathinfo($path, PATHINFO_EXTENSION) ?: 'unknown';
    }
}

<?php

namespace App\Services;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Parser;
use PhpParser\ParserFactory;

/**
 * Extracts conservative, source-level dataflow signals for one finding.
 *
 * The returned values deliberately describe code semantics only. Repository,
 * project, path and benchmark identifiers are never features, which prevents
 * the model from learning the identity of a benchmark instead of a weakness.
 */
class SourceDataflowFeatureExtractor
{
    private Parser $parser;

    /** @var array<string, string> */
    private const REQUEST_SUPERGLOBALS = [
        '_GET' => 'query',
        '_POST' => 'body',
        '_REQUEST' => 'request',
        '_COOKIE' => 'cookie',
        '_FILES' => 'file',
        '_SERVER' => 'server',
    ];

    /** @var array<string, array<string, string>> */
    private const SANITIZERS = [
        'command_execution' => [
            'escapeshellarg' => 'shell_argument_escape',
            'escapeshellcmd' => 'shell_command_escape',
        ],
        'sql_query' => [
            'mysqli_real_escape_string' => 'sql_escape',
            'mysqli_escape_string' => 'sql_escape',
            'pg_escape_literal' => 'sql_escape',
            'pg_escape_string' => 'sql_escape',
            'sqlite_escape_string' => 'sql_escape',
            'quote' => 'sql_escape',
        ],
        'html_output' => [
            'htmlspecialchars' => 'html_escape',
            'htmlentities' => 'html_escape',
            'e' => 'html_escape',
        ],
        'path_access' => [
            'basename' => 'path_basename',
        ],
    ];

    /** @var list<string> */
    private const APPLICATION_GENERATORS = [
        'app_path',
        'base_path',
        'database_path',
        'date',
        'hrtime',
        'microtime',
        'now',
        'public_path',
        'resource_path',
        'storage_path',
        'sys_get_temp_dir',
        'tempnam',
        'time',
        'uniqid',
        'uuid_create',
    ];

    public function __construct()
    {
        $this->parser = (new ParserFactory)->createForNewestSupportedVersion();
    }

    /**
     * @return array{
     *   source_status:string,
     *   analysis_status:string,
     *   sink_kind:string,
     *   argument_shape:string,
     *   attacker_context:string,
     *   request_reachable:bool,
     *   taint_steps:list<string>,
     *   sanitizer_on_path:bool,
     *   sanitizer_kind:string,
     *   value_origin:string
     * }
     */
    public function extract(
        string $absoluteFilePath,
        int $lineNumber,
        string $ruleId = '',
        ?int $cweId = null,
    ): array {
        if (! file_exists($absoluteFilePath)) {
            return $this->unknownResult('missing');
        }

        if (! is_file($absoluteFilePath) || ! is_readable($absoluteFilePath)) {
            return $this->unknownResult('unreadable');
        }

        $code = file_get_contents($absoluteFilePath);

        if ($code === false) {
            return $this->unknownResult('read_error');
        }

        if ($lineNumber < 1 || $lineNumber > substr_count($code, "\n") + 1) {
            return $this->unknownResult('line_out_of_range');
        }

        try {
            $ast = $this->parser->parse($code);
        } catch (Error) {
            return $this->unknownResult('parse_error');
        }

        if ($ast === null) {
            return $this->unknownResult('parse_error');
        }

        $hintedKind = $this->hintedSinkKind($ruleId, $cweId);
        $sink = $this->findSink($ast, $lineNumber, $hintedKind);

        if ($sink === null) {
            return [
                ...$this->unknownResult('available'),
                'analysis_status' => 'sink_not_found',
            ];
        }

        $scope = $this->findEnclosingScope($ast, $lineNumber);
        $assignments = $this->collectAssignments($scope ?? $ast, $scope);
        $traces = [];

        foreach ($sink['arguments'] as $argument) {
            $traces[] = $this->traceExpression(
                $argument,
                $assignments,
                $argument->getStartLine(),
                $sink['kind'],
                [],
            );
        }

        $trace = $this->mergeTraces($traces);

        if ($sink['sanitizer_kind'] !== null) {
            $trace['sanitizers'][] = $sink['sanitizer_kind'];
            $trace['sanitizers'] = array_values(array_unique($trace['sanitizers']));
        }

        $trace['steps'][] = 'sink:'.$sink['name'];

        return [
            'source_status' => 'available',
            'analysis_status' => 'analyzed',
            'sink_kind' => $sink['kind'],
            'argument_shape' => $this->argumentShape($sink['arguments']),
            'attacker_context' => $this->attackerContext($trace['contexts'], $trace['origin']),
            'request_reachable' => $trace['request_reachable'],
            'taint_steps' => array_values(array_unique($trace['steps'])),
            'sanitizer_on_path' => $trace['sanitizers'] !== [],
            'sanitizer_kind' => $this->sanitizerKind($trace['sanitizers']),
            'value_origin' => $trace['origin'],
        ];
    }

    /**
     * @return array{
     *   source_status:string,
     *   analysis_status:string,
     *   sink_kind:string,
     *   argument_shape:string,
     *   attacker_context:string,
     *   request_reachable:bool,
     *   taint_steps:list<string>,
     *   sanitizer_on_path:bool,
     *   sanitizer_kind:string,
     *   value_origin:string
     * }
     */
    private function unknownResult(string $sourceStatus): array
    {
        return [
            'source_status' => $sourceStatus,
            'analysis_status' => 'unavailable',
            'sink_kind' => 'unknown',
            'argument_shape' => 'unknown',
            'attacker_context' => 'unknown',
            'request_reachable' => false,
            'taint_steps' => [],
            'sanitizer_on_path' => false,
            'sanitizer_kind' => 'none',
            'value_origin' => 'unknown',
        ];
    }

    private function hintedSinkKind(string $ruleId, ?int $cweId): ?string
    {
        $byCwe = match ($cweId) {
            22, 23, 36, 73 => 'path_access',
            78 => 'command_execution',
            79, 80, 116 => 'html_output',
            89 => 'sql_query',
            502 => 'deserialization',
            915 => 'mass_assignment',
            default => null,
        };

        if ($byCwe !== null) {
            return $byCwe;
        }

        $rule = strtolower($ruleId);

        return match (true) {
            str_contains($rule, 'command'), str_contains($rule, 'shell') => 'command_execution',
            str_contains($rule, 'sql') => 'sql_query',
            str_contains($rule, 'path'), str_contains($rule, 'traversal'), str_contains($rule, 'file-inclusion') => 'path_access',
            str_contains($rule, 'xss'), str_contains($rule, 'unescaped') => 'html_output',
            str_contains($rule, 'deserial'), str_contains($rule, 'unserialize') => 'deserialization',
            str_contains($rule, 'mass-assignment') => 'mass_assignment',
            default => null,
        };
    }

    /**
     * @param  array<int, Node>  $ast
     * @return array{kind:string,name:string,arguments:list<Node\Expr>,sanitizer_kind:?string}|null
     */
    private function findSink(array $ast, int $lineNumber, ?string $hintedKind): ?array
    {
        $finder = new NodeFinder;
        $nodes = $finder->find($ast, static fn (Node $node): bool => $node->getStartLine() <= $lineNumber
            && $node->getEndLine() >= $lineNumber);
        $candidates = [];

        foreach ($nodes as $node) {
            $descriptor = $this->describeSink($node, $hintedKind);

            if ($descriptor === null) {
                continue;
            }

            $candidates[] = [
                'descriptor' => $descriptor,
                'hint_match' => $hintedKind === null || $descriptor['kind'] === $hintedKind,
                'exact_line' => $node->getStartLine() === $lineNumber,
                'span' => $node->getEndLine() - $node->getStartLine(),
            ];
        }

        if ($candidates === []) {
            return null;
        }

        usort($candidates, static fn (array $left, array $right): int => [
            (int) $right['hint_match'],
            (int) $right['exact_line'],
            -$right['span'],
        ] <=> [
            (int) $left['hint_match'],
            (int) $left['exact_line'],
            -$left['span'],
        ]);

        if ($hintedKind !== null && ! $candidates[0]['hint_match']) {
            return null;
        }

        return $candidates[0]['descriptor'];
    }

    /**
     * @return array{kind:string,name:string,arguments:list<Node\Expr>,sanitizer_kind:?string}|null
     */
    private function describeSink(Node $node, ?string $hintedKind): ?array
    {
        if ($node instanceof Node\Expr\ShellExec) {
            return $this->sinkDescriptor('command_execution', 'backtick', $node->parts);
        }

        if ($node instanceof Node\Stmt\Echo_) {
            return $this->sinkDescriptor('html_output', 'echo', $node->exprs);
        }

        if ($node instanceof Node\Expr\Print_) {
            return $this->sinkDescriptor('html_output', 'print', [$node->expr]);
        }

        if ($node instanceof Node\Expr\Include_) {
            return $this->sinkDescriptor('path_access', 'include', [$node->expr]);
        }

        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $name = strtolower($node->name->toString());
            $arguments = $this->argumentValues($node->args);

            if (in_array($name, ['exec', 'passthru', 'pcntl_exec', 'popen', 'proc_open', 'shell_exec', 'system'], true)) {
                return $this->sinkDescriptor('command_execution', $name, array_slice($arguments, 0, 1));
            }

            if (in_array($name, ['mysql_query', 'pg_query', 'sqlite_query'], true)) {
                return $this->sinkDescriptor('sql_query', $name, array_slice($arguments, -1));
            }

            if (in_array($name, ['mysqli_query', 'mysqli_real_query', 'mysqli_multi_query'], true)) {
                return $this->sinkDescriptor('sql_query', $name, isset($arguments[1]) ? [$arguments[1]] : []);
            }

            if (in_array($name, ['file', 'file_get_contents', 'file_put_contents', 'fopen', 'glob', 'mkdir', 'opendir', 'readfile', 'rmdir', 'scandir', 'unlink'], true)) {
                return $this->sinkDescriptor('path_access', $name, array_slice($arguments, 0, 1));
            }

            if (in_array($name, ['copy', 'rename'], true)) {
                return $this->sinkDescriptor('path_access', $name, array_slice($arguments, 0, 2));
            }

            if ($name === 'unserialize') {
                return $this->sinkDescriptor('deserialization', $name, array_slice($arguments, 0, 1));
            }

            if (in_array($name, ['printf', 'vprintf'], true)) {
                return $this->sinkDescriptor('html_output', $name, $arguments);
            }
        }

        if (($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall)
            && $node->name instanceof Node\Identifier
        ) {
            $name = strtolower($node->name->toString());
            $arguments = $this->argumentValues($node->args);

            if (in_array($name, ['query', 'select', 'selectraw', 'statement', 'unprepared'], true)) {
                return $this->sinkDescriptor('sql_query', $name, array_slice($arguments, 0, 1));
            }

            if ($name === 'exec' && $hintedKind === 'sql_query') {
                return $this->sinkDescriptor('sql_query', $name, array_slice($arguments, 0, 1));
            }

            if ($name === 'prepare') {
                return $this->sinkDescriptor('sql_query', $name, array_slice($arguments, 0, 1));
            }

            if (in_array($name, ['execute', 'bindparam', 'bindvalue'], true) && $hintedKind === 'sql_query') {
                $dataArguments = match ($name) {
                    'bindparam', 'bindvalue' => isset($arguments[1]) ? [$arguments[1]] : [],
                    default => $arguments,
                };

                return $this->sinkDescriptor('sql_query', $name, $dataArguments, 'parameter_binding');
            }

            if (in_array($name, ['create', 'fill', 'forcefill', 'update'], true) && $hintedKind === 'mass_assignment') {
                return $this->sinkDescriptor('mass_assignment', $name, array_slice($arguments, 0, 1));
            }
        }

        return null;
    }

    /**
     * @param  array<int, Node|scalar|null>  $arguments
     * @return array{kind:string,name:string,arguments:list<Node\Expr>,sanitizer_kind:?string}
     */
    private function sinkDescriptor(
        string $kind,
        string $name,
        array $arguments,
        ?string $sanitizerKind = null,
    ): array {
        return [
            'kind' => $kind,
            'name' => $name,
            'arguments' => array_values(array_filter(
                $arguments,
                static fn (mixed $argument): bool => $argument instanceof Node\Expr,
            )),
            'sanitizer_kind' => $sanitizerKind,
        ];
    }

    /**
     * @param  array<int, Node>  $ast
     */
    private function findEnclosingScope(array $ast, int $lineNumber): ?Node\FunctionLike
    {
        $finder = new NodeFinder;
        $scopes = $finder->find($ast, static fn (Node $node): bool => $node instanceof Node\FunctionLike
            && $node->getStartLine() <= $lineNumber
            && $node->getEndLine() >= $lineNumber);

        if ($scopes === []) {
            return null;
        }

        usort($scopes, static fn (Node $left, Node $right): int => ($left->getEndLine() - $left->getStartLine())
            <=> ($right->getEndLine() - $right->getStartLine()));

        $scope = $scopes[0];

        return $scope instanceof Node\FunctionLike ? $scope : null;
    }

    /**
     * @param  Node|array<int, Node>  $root
     * @return array<string, list<array{line:int,expression:Node\Expr}>>
     */
    private function collectAssignments(Node|array $root, ?Node\FunctionLike $selectedScope): array
    {
        $visitor = new class($selectedScope) extends NodeVisitorAbstract
        {
            /** @var array<string, list<array{line:int,expression:Node\Expr}>> */
            public array $assignments = [];

            public function __construct(private ?Node\FunctionLike $selectedScope) {}

            public function enterNode(Node $node): ?int
            {
                if ($node instanceof Node\FunctionLike && $node !== $this->selectedScope) {
                    return NodeTraverser::DONT_TRAVERSE_CHILDREN;
                }

                if ($node instanceof Node\Expr\Assign && $node->var instanceof Node\Expr\Variable
                    && is_string($node->var->name)
                ) {
                    $this->assignments[$node->var->name][] = [
                        'line' => $node->getStartLine(),
                        'expression' => $node->expr,
                    ];
                }

                return null;
            }
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($root instanceof Node ? [$root] : $root);

        return $visitor->assignments;
    }

    /**
     * @param  array<string, list<array{line:int,expression:Node\Expr}>>  $assignments
     * @param  array<string, true>  $seenVariables
     * @return array{origin:string,contexts:list<string>,request_reachable:bool,steps:list<string>,sanitizers:list<string>}
     */
    private function traceExpression(
        Node\Expr $expression,
        array $assignments,
        int $beforeLine,
        string $sinkKind,
        array $seenVariables,
    ): array {
        $superglobal = $this->superglobalName($expression);

        if ($superglobal !== null && isset(self::REQUEST_SUPERGLOBALS[$superglobal])) {
            $context = self::REQUEST_SUPERGLOBALS[$superglobal];

            return $this->trace('request', [$context], true, ['source:'.$superglobal]);
        }

        if ($superglobal === '_SESSION') {
            return $this->trace('session', [], false, ['source:_SESSION']);
        }

        if ($expression instanceof Node\Expr\Variable && is_string($expression->name)) {
            $name = $expression->name;

            if (isset($seenVariables[$name])) {
                return $this->trace('unknown', [], false, ['cycle:$'.$name]);
            }

            $definition = $this->latestAssignment($assignments[$name] ?? [], $beforeLine);

            if ($definition === null) {
                return $this->trace('unknown', [], false, ['unresolved:$'.$name]);
            }

            $seenVariables[$name] = true;
            $trace = $this->traceExpression(
                $definition['expression'],
                $assignments,
                $definition['line'],
                $sinkKind,
                $seenVariables,
            );
            $trace['steps'][] = 'assignment:$'.$name;

            return $trace;
        }

        if ($expression instanceof Node\Expr\BinaryOp\Concat) {
            $trace = $this->mergeTraces([
                $this->traceExpression($expression->left, $assignments, $beforeLine, $sinkKind, $seenVariables),
                $this->traceExpression($expression->right, $assignments, $beforeLine, $sinkKind, $seenVariables),
            ]);
            $trace['steps'][] = 'concatenation';

            return $trace;
        }

        if ($expression instanceof Node\Scalar\InterpolatedString) {
            $traces = [];

            foreach ($expression->parts as $part) {
                if ($part instanceof Node\Expr) {
                    $traces[] = $this->traceExpression($part, $assignments, $beforeLine, $sinkKind, $seenVariables);
                }
            }

            $trace = $this->mergeTraces($traces === [] ? [$this->trace('literal')] : $traces);
            $trace['steps'][] = 'interpolation';

            return $trace;
        }

        if ($expression instanceof Node\Expr\Array_) {
            $traces = [];

            foreach ($expression->items as $item) {
                $traces[] = $this->traceExpression($item->value, $assignments, $beforeLine, $sinkKind, $seenVariables);
            }

            $trace = $this->mergeTraces($traces === [] ? [$this->trace('literal')] : $traces);
            $trace['steps'][] = 'array';

            return $trace;
        }

        if ($expression instanceof Node\Expr\Ternary) {
            $branches = [$expression->if ?? $expression->cond, $expression->else];
            $trace = $this->mergeTraces(array_map(
                fn (Node\Expr $branch): array => $this->traceExpression(
                    $branch,
                    $assignments,
                    $beforeLine,
                    $sinkKind,
                    $seenVariables,
                ),
                $branches,
            ));
            $trace['steps'][] = 'conditional';

            return $trace;
        }

        if ($expression instanceof Node\Expr\Cast) {
            $trace = $this->traceExpression($expression->expr, $assignments, $beforeLine, $sinkKind, $seenVariables);
            $trace['steps'][] = 'cast';

            return $trace;
        }

        $directSource = $this->directCallSource($expression);

        if ($directSource !== null) {
            return $directSource;
        }

        $call = $this->callDetails($expression);

        if ($call !== null) {
            $sanitizer = self::SANITIZERS[$sinkKind][$call['name']] ?? null;
            $arguments = $call['arguments'];

            if ($sanitizer !== null) {
                $index = in_array($call['name'], ['mysqli_escape_string', 'mysqli_real_escape_string'], true) ? 1 : 0;
                $argument = $arguments[$index] ?? null;
                $trace = $argument === null
                    ? $this->trace('unknown')
                    : $this->traceExpression($argument, $assignments, $beforeLine, $sinkKind, $seenVariables);
                $trace['sanitizers'][] = $sanitizer;
                $trace['steps'][] = 'sanitizer:'.$call['name'];

                return $trace;
            }

            if (in_array($call['name'], self::APPLICATION_GENERATORS, true)) {
                $argumentTrace = $this->traceCallArguments($arguments, $assignments, $beforeLine, $sinkKind, $seenVariables);

                if ($argumentTrace['request_reachable'] || ! in_array($argumentTrace['origin'], ['literal', 'unknown'], true)) {
                    $argumentTrace['steps'][] = 'call:'.$call['name'];

                    return $argumentTrace;
                }

                return $this->trace('application_generated', [], false, ['generator:'.$call['name']]);
            }

            $trace = $this->traceCallArguments($arguments, $assignments, $beforeLine, $sinkKind, $seenVariables);
            $trace['steps'][] = 'call:'.$call['name'];

            return $trace;
        }

        if ($expression instanceof Node\Scalar
            || $expression instanceof Node\Expr\ConstFetch
            || $expression instanceof Node\Expr\ClassConstFetch
        ) {
            return $this->trace('literal', [], false, ['literal']);
        }

        if ($expression instanceof Node\Expr\ArrayDimFetch) {
            return $this->traceExpression($expression->var, $assignments, $beforeLine, $sinkKind, $seenVariables);
        }

        return $this->trace('unknown', [], false, ['unknown_expression']);
    }

    /**
     * @param  list<Node\Expr>  $arguments
     * @param  array<string, list<array{line:int,expression:Node\Expr}>>  $assignments
     * @param  array<string, true>  $seenVariables
     * @return array{origin:string,contexts:list<string>,request_reachable:bool,steps:list<string>,sanitizers:list<string>}
     */
    private function traceCallArguments(
        array $arguments,
        array $assignments,
        int $beforeLine,
        string $sinkKind,
        array $seenVariables,
    ): array {
        if ($arguments === []) {
            return $this->trace('unknown');
        }

        return $this->mergeTraces(array_map(
            fn (Node\Expr $argument): array => $this->traceExpression(
                $argument,
                $assignments,
                $beforeLine,
                $sinkKind,
                $seenVariables,
            ),
            $arguments,
        ));
    }

    /**
     * @return array{origin:string,contexts:list<string>,request_reachable:bool,steps:list<string>,sanitizers:list<string>}|null
     */
    private function directCallSource(Node\Expr $expression): ?array
    {
        if ($expression instanceof Node\Expr\FuncCall && $expression->name instanceof Node\Name) {
            $name = strtolower($expression->name->toString());

            if ($name === 'request') {
                return $this->trace('request', ['request'], true, ['source:request']);
            }

            if ($name === 'session') {
                return $this->trace('session', [], false, ['source:session']);
            }

            if (in_array($name, ['config', 'env'], true)) {
                return $this->trace('config', [], false, ['source:'.$name]);
            }

            if ($name === 'file_get_contents') {
                $firstArgument = $expression->args[0] ?? null;

                if ($firstArgument instanceof Node\Arg
                    && $firstArgument->value instanceof Node\Scalar\String_
                    && strtolower($firstArgument->value->value) === 'php://input'
                ) {
                    return $this->trace('request', ['raw_body'], true, ['source:php_input']);
                }
            }
        }

        if (($expression instanceof Node\Expr\MethodCall || $expression instanceof Node\Expr\NullsafeMethodCall)
            && $expression->name instanceof Node\Identifier
        ) {
            $name = strtolower($expression->name->toString());
            $context = match ($name) {
                'query' => 'query',
                'post' => 'body',
                'file' => 'file',
                'cookie' => 'cookie',
                'header', 'server' => 'server',
                'all', 'get', 'input', 'validated' => 'request',
                default => null,
            };

            if ($context !== null && $this->looksLikeRequestReceiver($expression->var)) {
                return $this->trace('request', [$context], true, ['source:request.'.$name]);
            }
        }

        if ($expression instanceof Node\Expr\StaticCall
            && $expression->class instanceof Node\Name
            && $expression->name instanceof Node\Identifier
        ) {
            $class = strtolower($expression->class->getLast());
            $name = strtolower($expression->name->toString());

            if (in_array($class, ['request', 'input'], true)
                && in_array($name, ['all', 'cookie', 'file', 'get', 'header', 'input', 'post', 'query'], true)
            ) {
                $context = match ($name) {
                    'query' => 'query',
                    'post' => 'body',
                    'file' => 'file',
                    'cookie' => 'cookie',
                    'header' => 'server',
                    default => 'request',
                };

                return $this->trace('request', [$context], true, ['source:request.'.$name]);
            }

            if ($class === 'session' && $name === 'get') {
                return $this->trace('session', [], false, ['source:session']);
            }

            if ($class === 'config' && $name === 'get') {
                return $this->trace('config', [], false, ['source:config']);
            }
        }

        return null;
    }

    private function looksLikeRequestReceiver(Node\Expr $receiver): bool
    {
        if ($receiver instanceof Node\Expr\Variable && is_string($receiver->name)) {
            return in_array(strtolower($receiver->name), ['request', 'req'], true);
        }

        if ($receiver instanceof Node\Expr\FuncCall && $receiver->name instanceof Node\Name) {
            return strtolower($receiver->name->toString()) === 'request';
        }

        return false;
    }

    /**
     * @return array{name:string,arguments:list<Node\Expr>}|null
     */
    private function callDetails(Node\Expr $expression): ?array
    {
        if ($expression instanceof Node\Expr\FuncCall && $expression->name instanceof Node\Name) {
            return [
                'name' => strtolower($expression->name->toString()),
                'arguments' => $this->argumentValues($expression->args),
            ];
        }

        if (($expression instanceof Node\Expr\MethodCall
                || $expression instanceof Node\Expr\NullsafeMethodCall
                || $expression instanceof Node\Expr\StaticCall)
            && $expression->name instanceof Node\Identifier
        ) {
            return [
                'name' => strtolower($expression->name->toString()),
                'arguments' => $this->argumentValues($expression->args),
            ];
        }

        return null;
    }

    /**
     * PHP-Parser 5 can expose VariadicPlaceholder entries in call argument
     * lists. Only real arguments carry a value expression.
     *
     * @param  array<int, Node\Arg|Node\VariadicPlaceholder>  $arguments
     * @return list<Node\Expr>
     */
    private function argumentValues(array $arguments): array
    {
        $values = [];

        foreach ($arguments as $argument) {
            if ($argument instanceof Node\Arg) {
                $values[] = $argument->value;
            }
        }

        return $values;
    }

    private function superglobalName(Node\Expr $expression): ?string
    {
        $root = $expression;

        while ($root instanceof Node\Expr\ArrayDimFetch) {
            $root = $root->var;
        }

        if (! $root instanceof Node\Expr\Variable || ! is_string($root->name)) {
            return null;
        }

        return strtoupper($root->name);
    }

    /**
     * @param  list<array{line:int,expression:Node\Expr}>  $definitions
     * @return array{line:int,expression:Node\Expr}|null
     */
    private function latestAssignment(array $definitions, int $beforeLine): ?array
    {
        $latest = null;

        foreach ($definitions as $definition) {
            if ($definition['line'] <= $beforeLine
                && ($latest === null || $definition['line'] >= $latest['line'])
            ) {
                $latest = $definition;
            }
        }

        return $latest;
    }

    /**
     * @param  list<Node\Expr>  $arguments
     */
    private function argumentShape(array $arguments): string
    {
        if ($arguments === []) {
            return 'none';
        }

        if (count($arguments) > 1) {
            return 'multiple';
        }

        $argument = $arguments[0];

        return match (true) {
            $argument instanceof Node\Scalar\InterpolatedString => 'interpolation',
            $argument instanceof Node\Scalar,
            $argument instanceof Node\Expr\ConstFetch,
            $argument instanceof Node\Expr\ClassConstFetch => 'literal',
            $argument instanceof Node\Expr\Variable => 'variable',
            $argument instanceof Node\Expr\BinaryOp\Concat => 'concatenation',
            $argument instanceof Node\Expr\FuncCall => 'function_call',
            $argument instanceof Node\Expr\MethodCall,
            $argument instanceof Node\Expr\NullsafeMethodCall,
            $argument instanceof Node\Expr\StaticCall => 'method_call',
            $argument instanceof Node\Expr\Array_ => 'array',
            $argument instanceof Node\Expr\ArrayDimFetch => 'array_access',
            $argument instanceof Node\Expr\PropertyFetch,
            $argument instanceof Node\Expr\NullsafePropertyFetch,
            $argument instanceof Node\Expr\StaticPropertyFetch => 'property_access',
            $argument instanceof Node\Expr\Ternary => 'conditional',
            default => 'expression',
        };
    }

    /**
     * @param  list<string>  $contexts
     */
    private function attackerContext(array $contexts, string $origin): string
    {
        $contexts = array_values(array_unique($contexts));

        if (count($contexts) > 1) {
            return 'mixed';
        }

        if ($contexts !== []) {
            return $contexts[0];
        }

        return $origin === 'unknown' ? 'unknown' : 'none';
    }

    /**
     * @param  list<string>  $sanitizers
     */
    private function sanitizerKind(array $sanitizers): string
    {
        $sanitizers = array_values(array_unique($sanitizers));

        return match (count($sanitizers)) {
            0 => 'none',
            1 => $sanitizers[0],
            default => 'multiple',
        };
    }

    /**
     * @param  list<array{origin:string,contexts:list<string>,request_reachable:bool,steps:list<string>,sanitizers:list<string>}>  $traces
     * @return array{origin:string,contexts:list<string>,request_reachable:bool,steps:list<string>,sanitizers:list<string>}
     */
    private function mergeTraces(array $traces): array
    {
        if ($traces === []) {
            return $this->trace('unknown');
        }

        $origins = [];
        $contexts = [];
        $steps = [];
        $sanitizers = [];
        $requestReachable = false;

        foreach ($traces as $trace) {
            $origins[] = $trace['origin'];
            $contexts = [...$contexts, ...$trace['contexts']];
            $steps = [...$steps, ...$trace['steps']];
            $sanitizers = [...$sanitizers, ...$trace['sanitizers']];
            $requestReachable = $requestReachable || $trace['request_reachable'];
        }

        return [
            'origin' => $this->mergeOrigins($origins),
            'contexts' => array_values(array_unique($contexts)),
            'request_reachable' => $requestReachable,
            'steps' => $steps,
            'sanitizers' => array_values(array_unique($sanitizers)),
        ];
    }

    /** @param list<string> $origins */
    private function mergeOrigins(array $origins): string
    {
        $origins = array_values(array_unique($origins));
        $meaningful = array_values(array_filter($origins, static fn (string $origin): bool => $origin !== 'literal'));

        if ($meaningful === []) {
            return 'literal';
        }

        if (count($meaningful) === 1) {
            return $meaningful[0];
        }

        $known = array_values(array_filter($meaningful, static fn (string $origin): bool => $origin !== 'unknown'));

        if (count(array_unique($known)) === 1) {
            return $known[0];
        }

        return 'mixed';
    }

    /**
     * @param  list<string>  $contexts
     * @param  list<string>  $steps
     * @return array{origin:string,contexts:list<string>,request_reachable:bool,steps:list<string>,sanitizers:list<string>}
     */
    private function trace(
        string $origin,
        array $contexts = [],
        bool $requestReachable = false,
        array $steps = [],
    ): array {
        return [
            'origin' => $origin,
            'contexts' => $contexts,
            'request_reachable' => $requestReachable,
            'steps' => $steps,
            'sanitizers' => [],
        ];
    }
}

<?php

namespace App\Services\Scanner;

use App\Models\Project;

/**
 * Reports what the scanner would actually walk for a project, before it walks
 * it.
 *
 * With several projects registered by absolute path it is easy to lose track
 * of which directories are in scope — and a silently-excluded folder looks
 * identical to a folder with no findings. This makes the boundary visible.
 */
class ScanTargetInspector
{
    /**
     * @return array{
     *   readable: bool,
     *   root: string|null,
     *   directories: list<array{name:string, included:bool, php_files:int}>,
     *   included_files: int,
     *   excluded_directories: list<string>
     * }
     */
    public function inspect(Project $project): array
    {
        $root = $project->source_path ? rtrim($project->source_path, '/\\') : null;

        if ($root === null || ! is_dir($root)) {
            return [
                'readable' => false,
                'root' => $root,
                'directories' => [],
                'included_files' => 0,
                'excluded_directories' => [],
            ];
        }

        $excluded = array_values(array_map('strtolower', (array) config('sast.scanner.exclude_directories', [])));
        $directories = [];
        $includedFiles = 0;

        foreach ((scandir($root) ?: []) as $entry) {
            if ($entry === '.' || $entry === '..' || ! is_dir($root.DIRECTORY_SEPARATOR.$entry)) {
                continue;
            }

            $included = ! in_array(strtolower($entry), $excluded, true);
            $count = $included ? $this->countPhpFiles($root.DIRECTORY_SEPARATOR.$entry, $excluded) : 0;
            $includedFiles += $count;

            $directories[] = [
                'name' => $entry,
                'included' => $included,
                'php_files' => $count,
            ];
        }

        // Loose .php files sitting at the project root are scanned too.
        $includedFiles += count(glob($root.DIRECTORY_SEPARATOR.'*.php') ?: []);

        usort($directories, function (array $a, array $b): int {
            return [$b['included'], $b['php_files']] <=> [$a['included'], $a['php_files']];
        });

        return [
            'readable' => true,
            'root' => $root,
            'directories' => $directories,
            'included_files' => $includedFiles,
            'excluded_directories' => array_values(array_filter(
                array_column($directories, 'name'),
                fn (string $name) => in_array(strtolower($name), $excluded, true)
            )),
        ];
    }

    /**
     * @param  list<string>  $excluded
     */
    private function countPhpFiles(string $directory, array $excluded): int
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS),
                fn (\SplFileInfo $current) => ! $current->isDir()
                    || ! in_array(strtolower($current->getFilename()), $excluded, true)
            ),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        $count = 0;

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                $count++;
            }
        }

        return $count;
    }
}

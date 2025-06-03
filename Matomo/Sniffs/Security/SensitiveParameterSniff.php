<?php

namespace Matomo\Sniffs\Security;

use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Files\File;

class SensitiveParameterSniff implements Sniff
{
    public $sensitiveKeywords = [
        'password',
    ];

    private $scalarTypes = [
        'string',
        'int',
        'float',
        'bool',
        'array',
        'mixed',
    ];

    public function register()
    {
        return [T_FUNCTION];
    }

    public function process(File $phpcsFile, $stackPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $openParen = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr);
        $closeParen = $tokens[$openParen]['parenthesis_closer'];

        for ($i = $openParen + 1; $i < $closeParen; $i++) {
            if ($tokens[$i]['code'] !== T_VARIABLE) {
                continue;
            }

            $paramName = ltrim($tokens[$i]['content'], '$');

            // Check if the parameter name contains a sensitive keyword
            if (!$this->isSensitiveName($paramName)) {
                continue;
            }

            // Find the type hint before the variable (if any)
            $typeHint = $this->getTypeHint($phpcsFile, $i);

            if ($typeHint !== null && !$this->isScalarType($typeHint)) {
                // Has a non-scalar type: skip
                continue;
            }

            $paramStartPtr = $phpcsFile->findPrevious([T_OPEN_PARENTHESIS, T_VARIABLE], $i - 1);

            // Check if #[\SensitiveParameter] is present
            if (!$this->hasSensitiveAttribute($phpcsFile, $i, $paramStartPtr)) {
                $phpcsFile->addError(
                    "Parameter \${$paramName} seems sensitive and has no complex type but is missing #[\\SensitiveParameter] attribute.",
                    $i,
                    'MissingSensitiveParameterAttribute'
                );
            }
        }
    }

    private function isSensitiveName(string $name): bool
    {
        foreach ($this->sensitiveKeywords as $keyword) {
            if (strtolower($name) === strtolower($keyword)) {
                return true;
            }
        }
        return false;
    }

    private function isScalarType(string $type): bool
    {
        return in_array(strtolower($type), $this->scalarTypes, true);
    }

    private function getTypeHint(File $phpcsFile, int $paramPtr): ?string
    {
        $tokens = $phpcsFile->getTokens();
        $i = $paramPtr - 1;

        while ($i > 0 && in_array($tokens[$i]['code'], [T_WHITESPACE, T_BITWISE_AND, T_ELLIPSIS])) {
            $i--;
        }

        if (in_array($tokens[$i]['code'], [T_STRING, T_ARRAY, T_CALLABLE, T_SELF, T_PARENT])) {
            return $tokens[$i]['content'];
        }

        if ($tokens[$i]['code'] === T_NS_SEPARATOR) {
            // Possibly a namespaced type
            $typeParts = [];
            while (in_array($tokens[$i]['code'], [T_STRING, T_NS_SEPARATOR])) {
                array_unshift($typeParts, $tokens[$i]['content']);
                $i--;
            }
            return implode('', $typeParts);
        }

        return null; // No type hint
    }

    private function hasSensitiveAttribute(File $phpcsFile, int $paramVarPtr, int $paramStartPtr): bool
    {
        $tokens = $phpcsFile->getTokens();

        for ($i = $paramStartPtr; $i < $paramVarPtr; $i++) {
            if ($tokens[$i]['code'] === T_STRING && $tokens[$i]['content'] === 'SensitiveParameter') {
                return true;
            }
        }

        return false;
    }
}

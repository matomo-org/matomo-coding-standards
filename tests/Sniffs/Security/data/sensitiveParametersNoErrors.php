<?php

class Whatever
{
    public function parameter(
        #[\SensitiveParameter]
        $password
    ) {
        // empty
    }

    public function parameterTypeHint(
        #[\SensitiveParameter]
        string $password
    ) {
        // empty
    }

    public function multipleParameters(
        $parameterBefore,
        #[\SensitiveParameter]
        $password,
        $parameterAfter
    ) {
        // empty
    }

    public function multipleSensitiveParameters(
        #[\SensitiveParameter]
        $password,
        #[\SensitiveParameter]
        $passwordNew
    ) {
        // empty
    }

    public function attributeAfter(
        #[\SensitiveParameter]
        #[AttributeAfter]
        $password
    ) {
        // empty
    }

    public function attributeBefore(
        #[AttributeBefore]
        #[\SensitiveParameter]
        $password
    ) {
        // empty
    }

    public function attributeCombination(
        #[AttributeBefore, \SensitiveParameter, AttributeAfter]
        $password
    ) {
        // empty
    }
}

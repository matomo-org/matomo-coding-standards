<?php

class Whatever
{
    #[SensitiveParameter]
    public function misplacedAttribute($password) {
        // empty
    }
}

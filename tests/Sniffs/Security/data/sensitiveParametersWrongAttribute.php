<?php

class Whatever
{
    public function wrongAttribute(
        #[SensitiveParameterButWrong]
        $password
    ) {
        // empty
    }
}

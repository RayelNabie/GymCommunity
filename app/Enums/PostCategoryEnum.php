<?php

namespace App\Enums;

enum PostCategoryEnum: string
{
    case KRACHT = 'kracht';
    case CARDIO = 'cardio';
    case VOEDING = 'voeding';
    case RECOVERY = 'recovery';

    public function label(): string
    {
        return match ($this) {
            self::KRACHT => 'Krachttraining',
            self::CARDIO => 'Conditie',
            self::VOEDING => 'Voeding',
            self::RECOVERY => 'Herstel',
        };
    }
}

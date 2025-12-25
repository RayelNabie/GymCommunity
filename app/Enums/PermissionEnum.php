<?php

namespace App\Enums;

enum PermissionEnum: string
{
    // Blog permissions
    case CREATE_POSTS = 'posts.create';
    case EDIT_ANY_POSTS = 'posts.edit_all';
    case PUBLISH_POSTS = 'posts.publish';

    // Agenda permissions
    case MANAGE_CLASSES = 'classes.manage';
    case BOOK_CLASSES = 'classes.book';

    // Admin permissions
    case MANAGE_USERS = 'users.manage';
    case VIEW_ANALYTICS = 'analytics.view';

    public function description(): string
    {
        return match ($this) {
            self::CREATE_POSTS => 'Nieuwe blogberichten of mededelingen schrijven',
            self::EDIT_ANY_POSTS => 'Berichten van andere trainers of coaches aanpassen',
            self::PUBLISH_POSTS => 'Berichten definitief live zetten voor leden',
            self::MANAGE_CLASSES => 'Trainingen aanmaken, tijden wijzigen en trainers toewijzen',
            self::BOOK_CLASSES => 'Jezelf inschrijven voor een groepsles of training',
            self::MANAGE_USERS => 'Lidmaatschappen beheren en accounts aanmaken',
            self::VIEW_ANALYTICS => 'Bezetting van de lessen en populariteit van blogs inzien',
        };
    }
}

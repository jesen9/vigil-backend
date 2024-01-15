<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Cwe extends Model
{
    use HasFactory;

    protected $table = 'cwe';

    protected $fillable = [
        'id',
        'name',
        'description'
    ];

    public $timestamps = false;

}

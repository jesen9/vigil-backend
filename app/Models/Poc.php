<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Poc extends Model
{
    use HasFactory;

    protected $table = 'poc';
    protected $fillable = [
        'cve_id',
        'title',
        'description',
        'link'
    ];
    public $timestamps = false;
}

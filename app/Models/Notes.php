<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Notes extends Model
{
    use HasFactory;

    protected $table = 'notes';
    protected $fillable = [
        'cve_id',
        'user_id',
        'notes',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}

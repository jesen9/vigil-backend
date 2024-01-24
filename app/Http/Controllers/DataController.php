<?php

namespace App\Http\Controllers;

use App\Models\Cwe;
use App\Models\Notes;
use App\Models\Poc;
use App\Models\User;
use Carbon\Carbon;
use Database\Seeders\DatabaseSeeder;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Env;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use function PHPUnit\Framework\isEmpty;

class DataController extends Controller
{
    # CVE

    public function getCveList(Request $request): \Illuminate\Http\JsonResponse
    {
        $results_per_page = $request->query->all()['resultsPerPage'] ?? false;
        $start_index = $request->query->all()['startIndex'] ?? false;

        if (!$results_per_page || $start_index === false) {
            return abort(response()->json([
                'message' => 'Pagination params not specified'
            ], 400));
        }

        $is_updated = isset($request->query->all()['isUpdated']);

        $req_query = collect($request->query->all())->filter(function($i, $key){
            return $key !== 'isUpdated';
        })->all();

        $query_string = Arr::query($req_query);

//        $rq = $request->getRequestUri();
//        dd($rq, parse_url($rq));

        $results_per_page = filter_var($results_per_page, FILTER_SANITIZE_NUMBER_INT);
        $start_index = filter_var($start_index, FILTER_SANITIZE_NUMBER_INT);

        if($is_updated){
            $query_string = str_replace("&isUpdated=true", "", $query_string);
        }
        $request_url = Env::get('NVD_API_URL')."?".$query_string;

        # PAGINATION LOGIC TO SORT BY NEWEST
        // get total pages (replace rpp and si to minimum value to reduce traffic
        // set replace pattern for rpp and si
        $results_per_page_pattern = '/resultsPerPage=[0-9]+/';
        $start_index_pattern = '/startIndex=[0-9]+/';
        // replace rpp and si in request_url
        $total_results_request = preg_replace($results_per_page_pattern, "resultsPerPage=1", $request_url);
        $total_results_request = preg_replace($start_index_pattern, "startIndex=0", $total_results_request);
        // request total pages
        $total_results_response = Http::get($total_results_request)->json();

        if(!$total_results_response){
            return abort(response()->json([
                'message' => 'No response from NVD API!'
            ], 500));
        }

        $total_results = $total_results_response['totalResults'];

        //calculate pages and indices
        $page_number = ($start_index/$results_per_page) + 1;
        $request_start_index =  max($total_results - $page_number * $results_per_page, 0);
        // Modify number of results in last page
        if($request_start_index === 0) $results_per_page = $total_results%$results_per_page;
        $request_url = preg_replace($results_per_page_pattern, "resultsPerPage=".$results_per_page, $request_url);
        $request_url = preg_replace($start_index_pattern, "startIndex=".$request_start_index, $request_url);

        $response = Http::get($request_url)->json();

        if(!$response){
            return abort(response()->json([
                'message' => 'No response from NVD API!'
            ], 500));
        }

        $cve_list = collect($response['vulnerabilities'] ?? [])->map(function($i){
            return $i['cve'];
        });
        if($is_updated){
            $cve_list = $cve_list->filter(function($i){
                $pub_date = Carbon::parse($i['published']);
                $mod_date = Carbon::parse($i['lastModified']);
                return $mod_date->gt($pub_date);
            });
            // some pages may have less than 20 results
//            $total_results = ;
        }

        $cve_list = $cve_list->map(function($i){
            $cve = [];
            $cve['cveid'] = $i['id'];
            $cve['description'] = collect($i['descriptions'] ?? [])->filter(function($j){
                return $j['lang'] == 'en';
            })->first()['value'];
            $pub_date = new \DateTime($i['published']);
            $cve['publishedat'] = $pub_date->format('d-m-Y');
            $upd_date = new \DateTime($i['lastModified']);
            $cve['updatedat'] = $upd_date->format('d-m-Y');
            $cve['cvssscore'] = collect($i['metrics'] ?? [])->collapse()->map(function($j){
                $cvss = $j['cvssData'];
                $cvss['source'] = $j['source'];
                $cvss['type'] = $j['type'];
                $cvss['exploitabilityScore'] = $j['exploitabilityScore'];
                $cvss['impactScore'] = $j['impactScore'];
                return $cvss;
            })->max('baseScore');
            return $cve;
        })->sortByDesc(function($i){
            return strtotime($i['publishedat']);
        })
        ->values();

        $cve_list = $cve_list->all();

        return response()->json([
            'resultsPerPage' => $results_per_page,
            'startIndex' => $start_index,
            'totalResults' => $total_results,
            'cvelist' => $cve_list
        ]);
    }

    public function getCveDetails(Request $request): \Illuminate\Http\JsonResponse
    {
        $cve_id = $request->query->all()['cveId'] ?? false;
        if (!$cve_id) {
            return abort(response()->json([
                'message' => 'CVE ID not provided'
            ], 400));
        }
        $request_url = Env::get('NVD_API_URL')."?cveId=".$cve_id;
        $cve_details = Http::get($request_url)->json();

        $cve = [];

        if(isset($cve_details['vulnerabilities'][0]['cve'])) {
            $cve_details = $cve_details['vulnerabilities'][0]['cve'];
            $cve['cveid'] = $cve_details['id'];
            $cve['description'] = collect($cve_details['descriptions'] ?? [])->filter(function ($j) {
                return $j['lang'] == 'en';
            })->first()['value'];
            $pub_date = new \DateTime($cve_details['published']);
            $cve['publishedat'] = $pub_date->format('d-m-Y');
            $upd_date = new \DateTime($cve_details['lastModified']);
            $cve['updatedat'] = $upd_date->format('d-m-Y');
            $cve['cvssscore'] = collect($cve_details['metrics'] ?? [])->collapse()->map(function ($j) {
                $cvss = $j['cvssData'];
                $cvss['source'] = $j['source'];
                $cvss['type'] = $j['type'];
                $cvss['exploitabilityScore'] = $j['exploitabilityScore'];
                $cvss['impactScore'] = $j['impactScore'];
                return $cvss;
            })->all();

            $cve['cwe'] = collect($cve_details['weaknesses'] ?? [])->map(function($j){
                $cwe = [];
                $cwe['cweid'] = collect($j['description'] ?? [])->filter(function($j){
                    return $j['lang'] == 'en';
                })->first()['value'];
                $cwe['name'] = Cwe::select('name')->where('id', $cwe['cweid'])->get()->toArray()[0]['name'] ?? 'Not found in database. Please update database.';
                $cwe['description'] = Cwe::select('description')->where('id', $cwe['cweid'])->get()->toArray()[0]['description'] ?? 'Not found in database. Please update database.';
                $cwe['source'] = $j['source'];
                $cwe['type'] = $j['type'];
                return $cwe;
            })->all();

            $cve['poc'] = $this->getPoc($cve_id);

            $cve['cpe'] = collect($cve_details['configurations'] ?? [])->map(function($i){
                return collect($i['nodes'])->map(function($j){
                    return $j['cpeMatch'];
                })->flatten(1);
            })->flatten(1)
                ->unique('matchCriteriaId')
                ->all();
        }

        return response()->json($cve);
    }

    # POC & CWE

    public function getPocByApi($cve_id): \Illuminate\Http\Client\Response
    {
        $api_key = Env::get('GOOGLE_API_KEY');
        $search_engine_id = Env::get('SEARCH_ENGINE_ID');
        $search_query = 'intitle:"'.$cve_id.'" poc';

        return Http::get(Env::get('GOOGLE_API_URL'), [
            'q' => $search_query,
            'key' => $api_key,
            'cx' => $search_engine_id,
            'exactTerms' => $cve_id,
            'num' => 5,
        ]);
    }

    public function getPoc($cve_id): array
    {
        $pocExists = Poc::where('cve_id', '=', $cve_id)->first();
        if(!isset($pocExists)) {
            $request = $this->getPocByApi($cve_id)->json()['items'] ?? [];
            if($request === []) return [];
            foreach($request as $poc_entry){
                $poc = new Poc();
                $poc->cve_id = $cve_id;
                $poc->title = $poc_entry['title'];
                $poc->description = $poc_entry['snippet'];
                $poc->link = $poc_entry['link'];
                $poc->save();
            }
        }
        return Poc::where('cve_id', '=', $cve_id)->get()->toArray() ?? [];
    }

    public function updateDatabase() {
        # CWE Database
        $page = 1;
        $cwe_data = [];

        // loop all CWE data in Opencve
        while(true) {
            set_time_limit(100);
            $response = HTTP::withBasicAuth(Env::get('OPENCVE_USERNAME'), Env::get('OPENCVE_PASSWORD'))
            ->get(Env::get('OPENCVE_CWE_API_URL'), [
                'page' => $page
            ]);

            if ($response->status() !== 200) break;

            $cwe_data = array_merge($cwe_data, $response->json());
            $page++;
        }

        if($cwe_data === []){
            if($response->json()['message'] == '250 per 1 hour') $cwe_status = "Request quota exceeded, failed to retrieve CWE data. Database is unchanged";
            else $cwe_status = "Failed to retrieve CWE data, database is unchanged.";
        }
        else {
            // Truncate (delete all entries from cwe table) before inserting new data
            Cwe::truncate();
            foreach($cwe_data as $cwe_entry){
                $cwe = new Cwe();
                $cwe->id = $cwe_entry['id'];
                $cwe->name = $cwe_entry['name'];
                $cwe->description = $cwe_entry['description'];
                $cwe->save();
            }
            $cwe_status = "CWE database updated.";
        }

        # POC Database
        $cve_ids = collect(Poc::select('cve_id')->get()->toArray())
            ->flatten()->unique()->values()->all();

        $poc_data = [];
        foreach($cve_ids as $cve_id){
            $request = $this->getPocByApi($cve_id)->json()['items'] ?? [];
            if($request === []) return [];
            foreach($request as $poc_entry){
                $poc = Poc::firstOrCreate(
                    ['cve_id' => $cve_id, 'link' => $poc_entry['link']],
                    ['title' => $poc_entry['title'], 'description' => $poc_entry['snippet']]
                )->get()->toArray();
                $poc_data = array_merge($poc_data, $poc);
            }
        }

        if($poc_data === []) {
            $poc_status = "No POC data retrieved, database is unchanged.";
        }
        else {
            $poc_status = "POC database updated.";
        }

        return response()->json([
            'message' => $cwe_status.' '.$poc_status
        ]);
    }

    # Notes

    public function insertNotes(Request $request) {
        $user_id = Auth::user()->id;
        $cve_id = $request->all()['cveId'] ?? false;
        $contents = $request->all()['notes'] ?? '';

        if(!$cve_id){
            return abort(response()->json([
                'message' => 'CVE ID not specified in request body'
            ], 400));
        }

        Notes::updateOrCreate(
            ['cve_id' => $cve_id, 'user_id' => $user_id],
            ['notes' => $contents]
        );

        return response()->json([
            'status' => 'Insert notes success!'
        ]);
    }

    public function getNotes(Request $request) {
        $user_id = Auth::user()->id;
        $keyword = $request->query->all()['keyword'] ?? false;
        $cve_id = $request->query->all()['cve_id'] ?? false;

        if($cve_id) {
            return Notes::where('user_id', '=', $user_id)->where(function($query) use ($cve_id)
            {
                $query->where('cve_id', '=', $cve_id);
            })->first();
        }
        else if($keyword) {
            return Notes::where('user_id', '=', $user_id)->where(function($query) use ($keyword)
            {
                $query->where('cve_id', 'like', '%'.$keyword.'%')
                    ->orWhere('notes', 'like', '%'.$keyword.'%');
            })->get();
        }
        else return Notes::where('user_id', '=', $user_id)->get();
    }

    public function deleteNotes($id) {
        $user_id = Auth::user()->id;
        $notesExists = Notes::where('id', $id)->first();

        if(isset($notesExists)) {
            $notes_user_id = Notes::where('id', $id)->first()->toArray()['user_id'];

            if($notes_user_id !== $user_id) return abort(response()->json([
                'message' => 'Forbidden'
            ], 403));

            Notes::where('id', (int)$id)->delete();
            return response()->json([
                'message' => 'Notes successfully deleted'
            ]);
        }
        else {
            return abort(response()->json([
                'message' => 'No such notes with specified ID found'
            ], 404));
        }
    }
}

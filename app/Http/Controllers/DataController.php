<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Env;
use Illuminate\Support\Facades\Http;
use function PHPUnit\Framework\isEmpty;

class DataController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
//        $cve_details = $this->getCveDetails($request);
//        dd($cve_details, $cve_details->json());
//        return Http::get('https://dog.ceo/api/breeds/list/random/5')['message'];
//        dd($breeds);
        //return view('index',compact('breeds'));
    }

    public function getCveList(Request $request) {
        /*
        $cpename = $request->query("cpeName");
        $cveId = $request->query("cveId");
        $cvssV3Metrics = $request->query("cvssV3Metrics");
        $cvssV3Severity = $request->query("cvssV3Severity");
        $cweId = $request->query("cweId");
        $hasCertAlerts = $request->query("hasCertAlerts");
        $hasCertNotes = $request->query("hasCertNotes");
        $hasKev = $request->query("hasKev");
        $hasOval = $request->query("hasOval");
        $isVulnerable = $request->query("isVulnerable");
        $keywordExactMatch = $request->query("keywordExactMatch");
        $keywordSearch = $request->query("keywordSearch");
        $virtualMatchString = $request->query("virtualMatchString");
        $noRejected = $request->query("noRejected");
        $resultsPerPage = $request->query("resultsPerPage");
        $startIndex = $request->query("startIndex");
        $sourceIdentifier = $request->query("sourceIdentifier");
        */

        //        lastModStartDate & lastModEndDate
        //        pubStartDate & pubEndDate
        //        versionEnd & versionEndType
        //        versionStart & versionStartType

        $results_per_page = $request->query->all()['resultsPerPage'] ?? false;
        $start_index = $request->query->all()['startIndex'] ?? false;
//        must add other params

        if (!$results_per_page || $start_index === false) {
            return abort(response()->json([
                'message' => 'Pagination params not specified'
            ], 400));
        }

        $query_string = parse_url($request->getRequestUri())['query'] ?? '';
        $request_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?".$query_string;

        $response = Http::get($request_url)->json();
        $cve_list = collect($response['vulnerabilities'])->map(function($i){
            return $i['cve'];
        })->map(function($i){
            $cve = [];
            $cve['cveid'] = $i['id'];
            $cve['description'] = collect($i['descriptions'])->filter(function($j){
                return $j['lang'] == 'en';
            })->first()['value'];
            $pub_date = new \DateTime($i['published']);
            $cve['publishedat'] = $pub_date->format('d-m-Y');
            $upd_date = new \DateTime($i['lastModified']);
            $cve['updatedat'] = $upd_date->format('d-m-Y');
            $cve['cvssscore'] = collect($i['metrics'])->collapse()->map(function($j){
                $cvss = $j['cvssData'];
                $cvss['source'] = $j['source'];
                $cvss['type'] = $j['type'];
                $cvss['exploitabilityScore'] = $j['exploitabilityScore'];
                $cvss['impactScore'] = $j['impactScore'];
                return $cvss;
            })->max('baseScore');
            return $cve;
        })->all();

        return response()->json([
            'resultsPerPage' => $response['resultsPerPage'],
            'startIndex' => $response['startIndex'],
            'totalResults' => $response['totalResults'],
            'cvelist' => $cve_list
        ]);
    }

    public function getCveDetails(Request $request) {
        $cve_id = $request->query->all()['cveId'] ?? false;
        if (!$cve_id) {
            return abort(response()->json([
                'message' => 'CVE ID not provided'
            ], 400));
        }
        $request_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=".$cve_id;
        $cve_details = Http::get($request_url)->json();
//        dd($cve_details, $cve_poc, [$cve_details, $cve_poc]); // json udh diubah jadi array, tinggal atur

        // harus pasang validasi, cve bisa jadi invalid jadi keluar vulnerabilities = []
        $cve = [];

        if(isset($cve_details['vulnerabilities'][0]['cve'])) {
            $cve_details = $cve_details['vulnerabilities'][0]['cve'];
            $cve['cveid'] = $cve_details['id'];
            $cve['description'] = collect($cve_details['descriptions'])->filter(function ($j) {
                return $j['lang'] == 'en';
            })->first()['value'];
            $pub_date = new \DateTime($cve_details['published']);
            $cve['publishedat'] = $pub_date->format('d-m-Y');
            $upd_date = new \DateTime($cve_details['lastModified']);
            $cve['updatedat'] = $upd_date->format('d-m-Y');
            $cve['cvssscore'] = collect($cve_details['metrics'])->collapse()->map(function ($j) {
//                cvss yg kepake:
//                {version}
//                {vectorString}
//                {baseScore}
//                {baseSeverity}
                $cvss = $j['cvssData'];
                $cvss['source'] = $j['source'];
                $cvss['type'] = $j['type'];
                $cvss['exploitabilityScore'] = $j['exploitabilityScore'];
                $cvss['impactScore'] = $j['impactScore'];
                return $cvss;
            })->all();

            $cve['cwe'] = collect($cve_details['weaknesses'])->map(function($j){
                $cwe = [];
                $cwe['cweid'] = collect($j['description'])->filter(function($j){
                    return $j['lang'] == 'en';
                })->first()['value'];
                $cwe['source'] = $j['source'];
                $cwe['type'] = $j['type'];
                return $cwe;
            })->all();

            $cve['poc'] = $this->getPoc($cve_id)->json()['items'] ?? [];
            if($cve['poc'] !== []){
                $cve['poc'] = collect($cve['poc'])->map(function($i){
                    $poc = [];
                    $poc['title'] = $i['title'];
                    $poc['description'] = $i['snippet'];
                    $poc['link'] = $i['link'];
                    return $poc;
                });
            }

            $cve['cpe'] = collect($cve_details['configurations'])->map(function($i){
                return collect($i['nodes'])->map(function($j){
                    return $j['cpeMatch'];
                })->flatten(1);
            })->flatten(1)
                ->unique('matchCriteriaId')
                ->all();
        }

        return response()->json($cve);
    }

    public function getPoc($cve_id) {
        $api_key = Env::get('GOOGLE_API_KEY');
        $search_engine_id = Env::get('SEARCH_ENGINE_ID');
        $search_query = 'intitle:"'.$cve_id.'" poc';

        return Http::get('https://www.googleapis.com/customsearch/v1', [
            'q' => $search_query,
            'key' => $api_key,
            'cx' => $search_engine_id,
            'exactTerms' => $cve_id,
            'num' => 5,
        ]);

    }

    public function getCpeDetails($cpe_uuid) {

    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }
}

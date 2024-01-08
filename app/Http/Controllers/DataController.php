<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Env;
use Illuminate\Support\Facades\Http;

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

//        dd($results_per_page, $start_index, 0 == false);

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
//            dd('ini first cve', $cve);
            return $cve;
        })->all();
//        ->all() ubah jadi array
        return response()->json($cve_list);

        /*{
            cveid:'CVE-2014-9174',
            description:'Cross-site scripting (XSS) vulnerability in the Google Analytics by Yoast (google-analytics-for-wordpress) plugin before 5.1.3 for WordPress allows remote attackers to inject arbitrary web script or HTML via the "Manually enter your UA code" (manual_ua_code_field) field in the General Settings.',
            cweid:'CWE-79',
            publishedat:' 2014-12-02 16:59:11',
            updatedat:'2017-09-08 01:29:33',
            cvssscore:'MEDIUM',
        }*/
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
        $cve_poc = $this->getPoc($cve_id)->json();
//        dd($cve_details, $cve_poc, [$cve_details, $cve_poc]); // json udh diubah jadi array, tinggal atur



        return response()->json($cve_details);
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
            'num' => 3,
        ]);

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

///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDAccess;
using Newtonsoft.Json.Linq;

namespace MDAdapter.MDClient.RestAPI
{
    internal class MDRestClient : IMDClient
    {
        private string serverEndpoint;
        private string apiKey;

        public void Initialize(string serverEndpoint, string apikey)
        {
            this.serverEndpoint = serverEndpoint;
            this.apiKey = apikey;
        }


        private MDResponse GetMDResponseFromStatusJSON(JObject parsedJson, string rawJSON)
        {
            MDResponse result = new MDResponse();
           
            try
            {
                result.DataId = (string)parsedJson["data_id"];
                result.FileName = (string)parsedJson["file_info"]["display_name"];
                result.RawJson = parsedJson.ToString(Newtonsoft.Json.Formatting.None);
                result.TotalEngines = (string)parsedJson["scan_results"]["total_avs"];
                result.Threat = (string)parsedJson["threat_name"];


                object dlpJSON = parsedJson["dlp_info"];
                if (dlpJSON != null)
                {
                    result.ResponseType = "DLP Result";
                }
                else
                {
                    result.ResponseType = "Multi-Scan Result";
                }

                if (parsedJson["process_info"] != null)
                {
                    if (parsedJson["process_info"]["verdicts"] != null)
                    {
                        result.Status = "processing";
                        JArray verdictArray = (JArray)parsedJson["process_info"]["verdicts"];

                        if (verdictArray.Count > 0)
                        {
                            result.Status = (string)verdictArray[0];
                        }
                    }
                }
            }
            catch (Exception)
            {
                result.RawJson = rawJSON;
            }

            return result;
        }



        private List<MDResponse> ParseGetStatusResultList(string json)
        {
            List<MDResponse> result = new List<MDResponse>();
            JArray parsedJson = JArray.Parse(json);
            
            foreach(JObject current in parsedJson)
            {
                MDResponse mdResponse = GetMDResponseFromStatusJSON(current, "");
                result.Add(mdResponse);
            }

            return result;
        }



        private MDResponse ParseGetStatusResult(string json)
        {
            JObject parsedJson = JObject.Parse(json);
            MDResponse result = GetMDResponseFromStatusJSON(parsedJson, json);

            return result;
        }


        public MDResponse GetStaus(string dataId)
        {
            string jsonResult = MDRestAPI.GetAnalysisResult(serverEndpoint, apiKey, dataId);
            MDResponse result = ParseGetStatusResult(jsonResult);

            return result;            
        }


        private MDResponse ParsePostFileResult(string json, string filePath)
        {
            MDResponse result = new MDResponse();

            try
            {
                JObject parsedJson = JObject.Parse(json);
                result.DataId = (string)parsedJson["data_id"];
                result.Status = (string)parsedJson["status"];
                result.RawJson = json;
                result.TotalEngines = "0";

                if (result.Status == null)
                {
                    result.Status = "inqueue";
                }

                if (!string.IsNullOrEmpty(filePath))
                {
                    FileInfo fileInfo = new FileInfo(filePath);
                    result.FileName = fileInfo.Name;
                }
            }
            catch (Exception e)
            {
                result.DataId = "Unknown";
                result.Status = "Failed to Post";
                result.FileName = filePath;
                result.RawJson = e.ToString();
                result.ResponseType = e.ToString();
                result.TotalEngines = "0";
            }

            return result;
        }



        public MDResponse PostFile(string filePath, MDRule rule)
        {
            string jsonResult = MDRestAPI.SubmitFileAsync(serverEndpoint, apiKey, filePath, rule.GetRuleString());
            MDResponse result = ParsePostFileResult(jsonResult, filePath);

            // return URI of the created resource.
            return result;
        }



        private MDRuleList ParseAvailableRulesResult(string json)
        {
            MDRuleList result = new MDRuleList();

            try
            {
                JArray parsedJson = JArray.Parse(json);
                foreach(JToken rule in parsedJson)
                {
                    result.Add((string)rule["name"]);
                }
            }
            catch (Exception)
            {
            }

            return result;
        }



        public MDRuleList GetAvailableRules()
        {
            MDRuleList result = new MDRuleList();
            string jsonResult = MDRestAPI.GetAnalysisRules(serverEndpoint, apiKey);
            result = ParseAvailableRulesResult(jsonResult);

            return result;
        }

        public MDResponse LookupHash(string hash)
        {
            MDResponse result = null;

            string jsonResult = MDRestAPI.LookupHash(serverEndpoint, apiKey, hash);
            if (jsonResult != null)
            {
                result = ParseGetStatusResult(jsonResult);
            }
            else
            {
                result = new MDResponse();
                result.FileName = hash;
            }

            return result;
        }

        public List<MDResponse> LookupHashList(List<string> hashList)
        {
            string jsonResult = MDRestAPI.LookupHashList(serverEndpoint, apiKey, hashList);
            List<MDResponse> result = ParseGetStatusResultList(jsonResult);
            
            return result;
        }
    }
}

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


        private MDResponse ParseGetStatusResult(string json)
        {
            MDResponse result = new MDResponse();

            try
            {
                JObject parsedJson = JObject.Parse(json);
                result.DataId = (string)parsedJson["data_id"];
                result.FileName = (string)parsedJson["file_info"]["display_name"];
                result.RawJson = json;
                result.TotalEngines = (string)parsedJson["scan_results"]["total_avs"];

                object dlpJSON = parsedJson["dlp_info"];
                if (dlpJSON != null)
                {
                    result.ResponseType = "DLP Result";
                }
                else
                {
                    result.ResponseType = "Multi-Scan Result";
                }

                if (parsedJson["process_info"]["verdicts"] != null)
                {
                    result.Status = "processing";
                    JArray verdictArray = (JArray)parsedJson["process_info"]["verdicts"];

                    if(verdictArray.Count > 0)
                    {
                        result.Status = (string)verdictArray[0];
                    }

                }
            }
            catch (Exception e)
            {
                result.RawJson = json;
            }


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
                FileInfo fileInfo = new FileInfo(filePath);
                JObject parsedJson = JObject.Parse(json);
                result.DataId = (string)parsedJson["data_id"];
                result.Status = (string)parsedJson["status"];
                result.FileName = fileInfo.Name;
                result.RawJson = json;
                result.TotalEngines = "0";

                if(result.Status == null)
                {
                    result.Status = "inqueue";
                }

            }
            catch(Exception e)
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
    }
}

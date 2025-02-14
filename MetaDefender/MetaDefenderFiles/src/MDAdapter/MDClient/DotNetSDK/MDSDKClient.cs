///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDAccess;
using MetaDefenderCommonSdk;
using MetaDefenderCommonSdk.Client;

namespace MDAdapter.MDClient.DotNetSDK
{
    internal class MDSDKClient : IMDClient
    {
        private MetaDefenderClient client;
        private string EndpointURI;

        void IMDClient.Initialize(string serverEndpoint, string apikey)
        {
            MetaDefenderClientConfig config = new MetaDefenderClientConfig
            {
                ApiKey = apikey,
                ScanProviderUrl = new Uri(serverEndpoint + "/file")
            };
            EndpointURI = serverEndpoint;

            client = new MetaDefenderClient(config);
        }


        MDResponse IMDClient.GetStaus(string dataId)
        {
            MDResponse result = new MDResponse();
            Task<FileLookupbydataidOkResponse> responseTask = Task.Run(() => client.Analysis.FetchFileAnalysisResultByDataId(dataId));

            result.DataId = responseTask.Result.DataId;
            result.Status = responseTask.Result.ProcessInfo.Result;
            result.FileName = responseTask.Result.FileInfo.DisplayName;

            result.RawJson = RestAPI.MDRestAPI.GetAnalysisResult(dataId, EndpointURI, client.ApiKey);
            result.TotalEngines = responseTask.Result.ScanResults.TotalAvs.ToString();

            if (responseTask.Result.DlpInfo != null)
            {
                result.ResponseType = "DLP Result";
            }
            else
            {
                result.ResponseType = "File Result";
            }

            return result;
        }


        MDResponse IMDClient.PostFile(string filePath, MDRule rule)
        {
            MDResponse result = new MDResponse();

            FileInfo fileInfo = new FileInfo(filePath);
            FileStream uploadFile = File.OpenRead(filePath);
            FileUploadRequest request = new FileUploadRequest(uploadFile);
            FileAnalysisOptions options = new FileAnalysisOptions(null, fileInfo.Name, null, null, null, null, null, rule.GetRuleString());

            //Task<FileUploadOkResponse> responseTask = client.Analysis.UploadFileToAnalyze(request,options,CancellationToken.None);
            Task<FileUploadOkResponse> responseTask = Task.Run(() => client.Analysis.UploadFileToAnalyze(request, options));

            result.DataId = responseTask.Result.DataId;
            result.Status = responseTask.Result.Status;
            result.FileName = fileInfo.Name;
            result.RawJson = "{}";
            result.TotalEngines = "0";

            return result;
        }
    }
}

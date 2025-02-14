///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDAccess;

namespace MDAdapter.MDClient
{
    public class MDFileAnalysis
    {
        IMDClient client = null;
        public MDFileAnalysis(string serverEndpoint, string apiKey)
        {
            client = MDClientFactory.GetSDKAccess(serverEndpoint, apiKey);
        }

        public List<MDResponse> ProcessFolder(string folderPath, MDRule rule)
        {

            List<MDResponse> result = new List<MDResponse>();

            if (!string.IsNullOrEmpty(folderPath))
            {
                if (Directory.Exists(folderPath))
                {

                    string[] files = Directory.GetFiles(folderPath);
                    foreach (string current in files)
                    {
                        MDResponse mdResult = client.PostFile(current, rule);
                        result.Add(mdResult);
                    }
                }
                else
                {
                    throw new Exception("The folder specified does not exist or is not a folder");
                }
            }
            else
            {
                throw new Exception("The Folder Path is blank");
            }

            return result;
        }

        public MDResponse GetStatus(string dataID)
        {
            return client.GetStaus(dataID);
        }

        private Stream GetSantizedFileStream(string dataID)
        {
            //Task<Stream> responseTask = Task.Run(() => client.Analysis.DownloadSanitizedFile(dataID));
            //return responseTask.Result;

            return null;
        }

        private List<string> GetDataIDListFromResponseList(List<MDResponse> responseList)
        {
            List<string> result = new List<string>();

            foreach (MDResponse response in responseList)
            {
                result.Add(response.DataId);
            }

            return result;
        }

        public List<MDResponse> UpdateStatusOnResponseList(List<MDResponse> responseList)
        {
            List<MDResponse> result;

            List<string> dataIdList = GetDataIDListFromResponseList(responseList);
            result = GetResponseFromDataIdList(dataIdList);

            return result;
        }


        public List<MDResponse> GetResponseFromDataIdList(List<string> dataIDList)
        {
            List<MDResponse> result = new List<MDResponse>();

            if (dataIDList != null && dataIDList.Count > 0)
            {
                foreach (string dataID in dataIDList)
                {
                    try
                    {
                        MDResponse fileAnalysisResponse = GetStatus(dataID);
                        result.Add(fileAnalysisResponse);
                    }
                    catch (Exception)
                    {
                        /*
                        // Get this directly with Rest
                        //TODO: Finish this up to be able to return the Analysis result.  Make sure to parse it accordingly.  Test a document that fails DLP
                        string jsonResult = MDRestAPI.GetAnalysisResult(dataID, serverEndpoint, apiKey);

                        MDResponse fileAnalysisResponse = new MDResponse(jsonResult,serverEndpoint,apiKey);
                        result.Add(fileAnalysisResponse);
                        */
                    }
                }
            }
            else
            {
                throw new Exception("Data ID list is empty.");
            }

            return result;
        }

        public void DownloadSanitizedFile(string dataID, string localFile)
        {
            Stream downloadStream = GetSantizedFileStream(dataID);

            FileStream localFileStream = File.Create(localFile);
            downloadStream.CopyTo(localFileStream);
            localFileStream.Close();
        }


    }
}

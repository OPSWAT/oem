///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDAccess;
using System.Security.Cryptography;
using System.Text;

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
                    catch (Exception e)
                    {
                        System.Console.WriteLine(e.Message);
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

        public MDRuleList GetRuleList()
        {
            return client.GetAvailableRules();
        }


        //TODO: Implement these functions tomorrow
        public MDResponse LookupHash(string hash)
        {
            return client.LookupHash(hash);
        }

        public List<MDResponse> LookupHashesFromListFile(string listFilePath, int maxEntries)
        {
            List<MDResponse> result = new List<MDResponse>();
            TextReader reader = new StreamReader(listFilePath);

            for(int i=0; i < maxEntries; i++)
            {
                string line = reader.ReadLine();
                MDResponse currentLineResponse = client.LookupHash(line);
                result.Add(currentLineResponse);
            }

            return result;
        }


        private static string GetMd5HashOfFile(string filePath)
        {
            string result = null;

            try
            {
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        byte[] hashBytes = md5.ComputeHash(stream);
                        StringBuilder sb = new StringBuilder();
                        foreach (byte b in hashBytes)
                        {
                            sb.Append(b.ToString("x2"));
                        }
                        result = sb.ToString();
                    }
                }
            }
            catch (Exception) { }

            return result;
        }

        public List<MDResponse> LookupHashesFileFolder(string fileFolderPath, int maxEntries)
        {
            List<MDResponse> result = new List<MDResponse>();

            DirectoryInfo directoryInfo = new DirectoryInfo(fileFolderPath);

            int count = 0;
            foreach (FileInfo fileInfo in directoryInfo.GetFiles())
            {
                string md5Hash = GetMd5HashOfFile(fileInfo.FullName);

                if (!string.IsNullOrEmpty(md5Hash))
                {
                    MDResponse currentLineResponse = client.LookupHash(md5Hash);
                    result.Add(currentLineResponse);

                    if (count >= maxEntries)
                    {
                        break;
                    }
                    count++;
                }
            }

            return result;
        }

    }
}

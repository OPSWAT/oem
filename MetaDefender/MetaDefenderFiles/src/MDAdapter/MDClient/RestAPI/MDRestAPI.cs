///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using System.Net;

namespace MDAdapter.MDClient.RestAPI
{
    public class MDRestAPI
    {

        public static string SubmitFileAsync(string serverEndpoint, string apikey, string filePath,string rule)
        {
            string requestUrl = serverEndpoint + "/file";
            string result = null;

            //ComponentResposne reference = null;
            using (var httpClient = new HttpClient())
            {
                FileInfo fileInfo = new FileInfo(filePath);
                httpClient.DefaultRequestHeaders.Add("apikey", apikey);
                httpClient.DefaultRequestHeaders.Add("filename", fileInfo.Name);
                httpClient.DefaultRequestHeaders.Add("rule", rule);

                HttpContent fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

                //add file part
                var response = httpClient.PostAsync(requestUrl, fileContent).Result;
                string responseText = response.StatusCode + ":" + response.ReasonPhrase;

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    result = response.Content.ReadAsStringAsync().Result;
                }
                else
                {
                    Console.WriteLine("Failed to access sanitized file: " + response.StatusCode + ":" + response.ReasonPhrase);
                }

            }

            // return URI of the created resource.
            return result;
        }




        /*
        public static string SubmitHash(string hash, string serverEndpoint, string apikey)
        {
            string result = null;

            // https://api.metadefender.com/v4/hash/6A5C19D9FFE8804586E8F4C0DFCC66DE
            string requestUrl = ServerURL + "/hash/" + hash;
            //string requestUrl = "https://api.metadefender.com/v4/hash/4EE607983947E486DBE488B1731C01C1AEEFEDD82619FDF35DBF2E52DFA32D41";

            try
            {

                //ComponentResposne reference = null;
                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.Add("apiKey", ApiKey);
                    //httpClient.DefaultRequestHeaders.Add("skippartialresults", "1");

                    var response = httpClient.GetAsync(requestUrl).Result;
                    string responseText = response.StatusCode + ":" + response.ReasonPhrase;

                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        result = response.Content.ReadAsStringAsync().Result;
                    }
                }
            }
            catch (Exception)
            { }

            return result;
        }
        */

        public static string GetAnalysisResult(string serverEndpoint, string apikey, string dataID)
        {
            string result = null;
            string requestUrl = serverEndpoint + "/file/" + dataID;

            try
            {

                //ComponentResposne reference = null;
                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.Add("apiKey", apikey);

                    var response = httpClient.GetAsync(requestUrl).Result;
                    string responseText = response.StatusCode + ":" + response.ReasonPhrase;

                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        result = response.Content.ReadAsStringAsync().Result;
                    }
                }
            }
            catch (Exception)
            { }

            return result;
        }



    }
}

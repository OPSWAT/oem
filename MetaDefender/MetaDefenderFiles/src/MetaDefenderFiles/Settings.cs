///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using System.Text.Json;

namespace MetaDefenderFiles
{
    internal class Settings
    {
        private string serverEndpoint;
        private string apikey;
        private string scanFolder;
        private string rule;
        private bool   cloudEndpoint;

        public string ServerEndpoint { get => serverEndpoint; set => serverEndpoint = value; }
        public string Apikey { get => apikey; set => apikey = value; }
        public string ScanFolder { get => scanFolder; set => scanFolder = value; }
        public string Rule { get => rule; set => rule = value; }
        public bool CloudEndpoint { get => cloudEndpoint; set => cloudEndpoint = value; }


        public void Serialize()
        {
            File.WriteAllText("settings.json",JsonSerializer.Serialize(this));
        }


        public static Settings Deserialize()
        {
            Settings result = new Settings(); 
            if(File.Exists("settings.json"))
            {
                string json = File.ReadAllText("settings.json");
                result = JsonSerializer.Deserialize<Settings>(json);
            }

            return result;
        }


        public string GetServerEndpointAddress()
        {
            string result = null;

            if (cloudEndpoint)
            {
                result = "https://api.metadefender.com/v4";
            }
            else
            {
                result = ServerEndpoint;
            }

            return result;
        }




    }
}

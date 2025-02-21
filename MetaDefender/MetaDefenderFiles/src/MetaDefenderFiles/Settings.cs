///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDClient;
using System.Text.Json;

namespace MetaDefenderFiles
{
    internal class Settings
    {
        private string serverEndpoint;
        private string apikey;
        private int    selectionTab;
        
        
        private string scanFolder;
        private string rule;
        private bool   cloudEndpoint;
        private string customRule;
        
        private MDHashProcess hashProcess;
        private string hashSingle;
        private string hashFile;
        private string hashFileFolder;




        public string ServerEndpoint { get => serverEndpoint; set => serverEndpoint = value; }
        public string Apikey { get => apikey; set => apikey = value; }
        public string ScanFolder { get => scanFolder; set => scanFolder = value; }
        public string Rule { get => rule; set => rule = value; }
        public bool CloudEndpoint { get => cloudEndpoint; set => cloudEndpoint = value; }
        public string CustomRule { get => customRule; set => customRule = value; }
        public MDHashProcess HashProcess { get => hashProcess; set => hashProcess = value; }
        public string HashSingle { get => hashSingle; set => hashSingle = value; }
        public string HashFile { get => hashFile; set => hashFile = value; }
        public string HashFileFolder { get => hashFileFolder; set => hashFileFolder = value; }
        public int SelectionTab { get => selectionTab; set => selectionTab = value; }

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

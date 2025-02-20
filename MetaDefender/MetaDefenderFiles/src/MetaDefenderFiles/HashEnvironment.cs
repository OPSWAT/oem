///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////
using MDAdapter.MDClient;

namespace MetaDefenderFiles
{
    internal class HashEnvironment
    {
        string serverEndpoint;
        string apikey;

        MDHashProcess hashProcess;
        string single;
        string listFile;
        string fileFolder;

        public MDHashProcess HashProcess { get => hashProcess; set => hashProcess = value; }
        public string Single { get => single; set => single = value; }
        public string ListFile { get => listFile; set => listFile = value; }
        public string FileFolder { get => fileFolder; set => fileFolder = value; }
        public string ServerEndpoint { get => serverEndpoint; set => serverEndpoint = value; }
        public string Apikey { get => apikey; set => apikey = value; }
    }
}

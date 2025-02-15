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
    internal class WorkerEnvironment
    {
        MDRule rule;
        string serverEndpoint;
        string apikey;

        public MDRule Rule { get => rule; set => rule = value; }
        public string ServerEndpoint { get => serverEndpoint; set => serverEndpoint = value; }
        public string Apikey { get => apikey; set => apikey = value; }
    }
}

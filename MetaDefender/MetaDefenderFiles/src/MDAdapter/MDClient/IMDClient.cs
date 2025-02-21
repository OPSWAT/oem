///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDClient;

namespace MDAdapter.MDAccess
{
    internal interface IMDClient
    {
        void Initialize(string serverEndpoint, string apikey);

        public MDResponse GetStaus(string dataId);

        public MDResponse PostFile(string filePath, MDRule rule);

        public MDRuleList GetAvailableRules();

        public MDResponse LookupHash(string hash);

        public List<MDResponse> LookupHashList(List<string> hashList);
    }
}

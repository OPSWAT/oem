///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

namespace MDAdapter.MDClient
{
    public class MDResponse
    {
        //
        // Member variables
        //
        public string DataId;
        public string Status;
        public string FileName;
        public string RawJson;
        public string TotalEngines;
        public string ResponseType;
        public string Threat;

        public MDResponse()
        {
        }
              
    }
}

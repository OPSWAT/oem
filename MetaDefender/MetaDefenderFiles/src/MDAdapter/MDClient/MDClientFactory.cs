///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDClient.RestAPI;

namespace MDAdapter.MDAccess
{
    internal class MDClientFactory
    {
        public static IMDClient GetSDKAccess(string endpointAddress, string apikey)
        {
            //
            // This method controls the different access methods to the MetaDefender API
            //
            // 1.  The first method is making direct RestAPI calls to the SDK.  This is useful for full flexibility, but
            // does require you parsing the results and building the JSON.  This is also great place to get some sample code or understand the
            // api for porting to a differnt programming language.
            //
            // 2. The second method is to use the Dot Net version of the SDK that we have for accessing the MetaDefender Server directly
            // this allows for a quicker interation and will be contiually supportted by OPSWAT with parsing.  But is not quite as flexible as direct call.


            // This is the method for using the 2. option above.  Using the OPSWAT supportted Dot Net SDK
            IMDClient client = new MDRestClient();
            client.Initialize(endpointAddress, apikey);


            // This is the method for using the 2. option above.  Using the OPSWAT supportted Dot Net SDK
            //IMDClient client = new MDSDKClient();
            //client.Initialize(endpointAddress, apikey);

            return client;
        }
    }
}

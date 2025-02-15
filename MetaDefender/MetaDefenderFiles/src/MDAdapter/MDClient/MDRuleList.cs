///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

namespace MDAdapter.MDClient
{
    public class MDRuleList : List<string>
    {
        public void AddRule(string rule)
        {
            this.Add(rule);
        }
    }
}

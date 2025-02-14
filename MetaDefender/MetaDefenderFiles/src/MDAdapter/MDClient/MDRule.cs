///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

namespace MDAdapter.MDClient
{
    public class MDRule
    {
        private string rule;

        public enum CloudRule
        {
            dlp,
            multiscan,
            sanitize,
            cdr,
            unarchive
        }

        public void SetCustomRule(string rule)
        {
            this.rule = rule;
        }

        public void SetCloudRule(CloudRule rule)
        {
            this.rule = rule.ToString();
        }

        public string GetRuleString()
        {
            return rule;
        }
    }
}

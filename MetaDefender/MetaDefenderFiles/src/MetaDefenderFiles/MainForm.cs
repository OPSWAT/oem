///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDClient;
using System.ComponentModel;

namespace MetaDefenderFiles
{
    public partial class MainForm : Form
    {
        private List<MDResponse> processFileList = new List<MDResponse>();
        private BackgroundWorker scanWorker;
        private BackgroundWorker statusWorker;



        public MainForm()
        {
            InitializeComponent();
            HideLoading();
            LoadSettings();
            InitializeBackgroundWorkers();
        }


        private void HideLoading()
        {
            pbLoading.Visible = false;
        }

        private void ShowLoading()
        {
            pbLoading.Visible = true;
        }



        // Set up the BackgroundWorker object by
        // attaching event handlers.
        private void InitializeBackgroundWorkers()
        {
            scanWorker = new BackgroundWorker();
            scanWorker.DoWork +=
                new DoWorkEventHandler(scanWorker_DoWork);
            scanWorker.RunWorkerCompleted +=
                new RunWorkerCompletedEventHandler(
            scanWorker_Completed);

            statusWorker = new BackgroundWorker();
            statusWorker.DoWork +=
                new DoWorkEventHandler(statusWorker_DoWork);
            statusWorker.RunWorkerCompleted +=
                new RunWorkerCompletedEventHandler(
            statusWorker_Completed);


        }



        private void LoadSettings()
        {
            Settings settings = Settings.Deserialize();
            tbApiKey.Text = settings.Apikey;
            tbServerEndpoint.Text = settings.ServerEndpoint;
            tbTargetFolderPath.Text = settings.ScanFolder;

            if (!settings.CloudEndpoint)
            {
                rbOnPremEndpoint.Checked = true;
            }
            else
            {
                rbCloudEndpoint.Checked = true;
            }

            switch (settings.Rule)
            {
                case "dlp":
                    {
                        rbDLP.Checked = true;
                        break;
                    }
                case "multiscan":
                    {
                        rbMultiscan.Checked = true;
                        break;
                    }
                case "sanitize":
                    {
                        rbSanitize.Checked = true;
                        break;
                    }
                case "cdr":
                    {
                        rbCDR.Checked = true;
                        break;
                    }
                case "unarchive":
                    {
                        rbUnarchive.Checked = true;
                        break;
                    }
                default:
                    {
                        rbCustom.Checked = true;
                        tbCustomRule.Text = settings.CustomRule;
                        break;
                    }
            }
        }

        private void SaveSettings()
        {
            Settings settings = new Settings();
            settings.Apikey = tbApiKey.Text;
            settings.ServerEndpoint = tbServerEndpoint.Text;
            settings.ScanFolder = tbTargetFolderPath.Text;

            if (rbCloudEndpoint.Checked)
            {
                settings.CloudEndpoint = true;
            }
            else
            {
                settings.CloudEndpoint = false;
            }

            if(rbCustom.Checked)
            {
                settings.Rule = "custom";
                settings.CustomRule = tbCustomRule.Text;
            }
            else
            {
                MDRule mdRule = GetMDRule();
                settings.Rule = mdRule.GetRuleString();
            }


            settings.Serialize();
        }

        private Settings getSettings()
        {
            SaveSettings();
            return Settings.Deserialize();
        }

        private MDFileAnalysis getFileAnalyzer()
        {
            CheckConnectionInfo();

            Settings settings = getSettings();
            MDFileAnalysis fileAnalyzer = new MDFileAnalysis(settings.GetServerEndpointAddress(), settings.Apikey);

            return fileAnalyzer;
        }



        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///  Worker Threads
        /// </summary>
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void scanWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                MDFileAnalysis fileAnalyzer = getFileAnalyzer();

                MDRule rule = GetMDRule();
                List<MDResponse> processFileTempResult = fileAnalyzer.ProcessFolder(tbTargetFolderPath.Text, rule);
                processFileList = processFileTempResult;
            }
            catch (Exception runningException)
            {
                MessageBox.Show(runningException.Message);
            }
        }

        private void scanWorker_Completed(object sender, RunWorkerCompletedEventArgs e)
        {
            UpdateProcessingList();
            HideLoading();
        }


        private void statusWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                MDFileAnalysis fileAnalyzer = getFileAnalyzer();

                MDRule rule = GetMDRule();
                List<MDResponse> processFileTempResult = fileAnalyzer.UpdateStatusOnResponseList(processFileList);
                processFileList = processFileTempResult;
            }
            catch (Exception runningException)
            {
                MessageBox.Show(runningException.Message);
            }

        }

        private void statusWorker_Completed(object sender, RunWorkerCompletedEventArgs e)
        {
            UpdateProcessingList();
            HideLoading();
        }


        private string GetSettingServerEndpointAddress()
        {
            SaveSettings();
            Settings settings = Settings.Deserialize();
            string serverEndpoint = settings.GetServerEndpointAddress();

            return serverEndpoint;
        }


        private void CheckConnectionInfo()
        {
            if (string.IsNullOrEmpty(tbApiKey.Text))
            {
                throw new Exception("The APIKey is required to run this request.");
            }

            string serverEndpoint = GetSettingServerEndpointAddress();
            if (string.IsNullOrEmpty(serverEndpoint))
            {
                throw new Exception("\"The Server Endpoint needs to be specified.  It should be in the format of \\\"https://%serverAddress%//v4\\\"");
            }
            
        }

        private void rbOnPremEndpoint_CheckedChanged(object sender, EventArgs e)
        {
            if (rbOnPremEndpoint.Checked == true)
            {
                tbServerEndpoint.Enabled = true;
                rbCDR.Enabled = false;
                rbDLP.Enabled = false;
                rbMultiscan.Enabled = false;
                rbSanitize.Enabled = false;
                rbCustom.Enabled = true;
                rbCustom.Checked = true;
            }
            else
            {
                tbServerEndpoint.Enabled = false;
                rbCDR.Enabled = true;
                rbDLP.Enabled = true;
                rbMultiscan.Enabled = true;
                rbSanitize.Enabled = true;
                rbCustom.Enabled = false;
                rbMultiscan.Checked = true;
            }
        }

        private void rbCustom_CheckedChanged(object sender, EventArgs e)
        {
            if (rbCustom.Checked == true)
            {
                tbCustomRule.Enabled = true;
            }
            else
            {
                tbCustomRule.Enabled = false;
            }
        }

        private MDRule GetMDRule()
        {
            MDRule result = new MDRule();

            if (rbCustom.Checked)
            {
                result.SetCustomRule(tbCustomRule.Text);
            }
            else
            {
                if (rbMultiscan.Checked)
                {
                    result.SetCloudRule(MDRule.CloudRule.multiscan);
                }
                else if (rbDLP.Checked)
                {
                    result.SetCloudRule(MDRule.CloudRule.dlp);
                }
                else if (rbSanitize.Checked)
                {
                    result.SetCloudRule(MDRule.CloudRule.sanitize);
                }
                else if (rbUnarchive.Checked)
                {
                    result.SetCloudRule(MDRule.CloudRule.unarchive);
                }
            }

            return result;
        }

        private void UpdateProcessingList()
        {

            foreach (MDResponse current in processFileList)
            {
                ListViewItem item = new ListViewItem(current.FileName);
                item.SubItems.Add(current.Status);
                item.SubItems.Add(current.TotalEngines);
                item.SubItems.Add(current.ResponseType);
                item.Tag = current;

                lvScanResult.Items.Add(item);

            }
        }

        private string GetServerEndpoint()
        {
            string result = "";
            if(rbCloudEndpoint.Checked)
            {
                result = "https://api.metadefender.com/v4";
            }
            else
            {
                result = tbServerEndpoint.Text;
            }

            return result;
        }

        private void btnProcessFiles_Click(object sender, EventArgs e)
        {
            lvScanResult.Items.Clear();
            ShowLoading();
            scanWorker.RunWorkerAsync(false);
        }

        private void btnBrowseFolder_Click(object sender, EventArgs e)
        {
            folderBrowserDialog1.ShowDialog();
            tbTargetFolderPath.Text = folderBrowserDialog1.SelectedPath;
        }

        private void btnRefreshStatus_Click(object sender, EventArgs e)
        {
            lvScanResult.Items.Clear();
            ShowLoading();
            statusWorker.RunWorkerAsync(false);
        }

        private void btnShowKey_Click(object sender, EventArgs e)
        {
            MessageBox.Show(tbApiKey.Text);
        }
    }
}

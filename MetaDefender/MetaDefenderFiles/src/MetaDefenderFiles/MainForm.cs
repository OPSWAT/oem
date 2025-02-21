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
        private BackgroundWorker fileScanWorker;
        private BackgroundWorker fileStatusWorker;

        private BackgroundWorker hashLookupWorker;



        public MainForm()
        {
            InitializeComponent();
            HideLoading(pbFileScanLoading);
            HideLoading(pbHashLookupLoading);

            LoadSettings();
            InitializeBackgroundWorkers();
        }


        private void HideLoading(PictureBox loadingPix)
        {
            loadingPix.Visible = false;
        }

        private void ShowLoading(PictureBox loadingPix)
        {
            loadingPix.Visible = true;
        }

        // Set up the BackgroundWorker object by
        // attaching event handlers.
        private void InitializeBackgroundWorkers()
        {
            // Scan File Workers
            fileScanWorker = new BackgroundWorker();
            fileScanWorker.DoWork +=
                new DoWorkEventHandler(FileScanWorker_DoWork);
            fileScanWorker.RunWorkerCompleted +=
                new RunWorkerCompletedEventHandler(
            FileScanWorker_Completed);

            fileStatusWorker = new BackgroundWorker();
            fileStatusWorker.DoWork +=
                new DoWorkEventHandler(FileStatusWorker_DoWork);
            fileStatusWorker.RunWorkerCompleted +=
                new RunWorkerCompletedEventHandler(
            FileStatusWorker_Completed);


            // Lookup Hash Workers
            hashLookupWorker = new BackgroundWorker();
            hashLookupWorker.DoWork +=
                new DoWorkEventHandler(HashLookupWorker_DoWork);
            hashLookupWorker.RunWorkerCompleted +=
                new RunWorkerCompletedEventHandler(
            HashLookupWorker_Completed);

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
                        cbRuleListBox.Text = settings.CustomRule;
                        break;
                    }
            }

            switch (settings.HashProcess)
            {
                case MDHashProcess.single:
                    {
                        rbHashSingle.Checked = true;
                        break;
                    }
                case MDHashProcess.listfile:
                    {
                        rbHashListFile.Checked = true;
                        break;
                    }
                case MDHashProcess.filefolder:
                    {
                        rbHashFileFolder.Checked = true;
                        break;
                    }
                default:
                    {
                        break;
                    }

            }

            tbHashSingle.Text = settings.HashSingle;
            tbHashListFile.Text = settings.HashFile;
            tbHashFileFolder.Text = settings.HashFileFolder;


            tbMainTabs.SelectTab(settings.SelectionTab);
        }

        private void SaveSettings()
        {
            Settings settings = new Settings();
            settings.Apikey = tbApiKey.Text;
            settings.ServerEndpoint = tbServerEndpoint.Text;
            settings.ScanFolder = tbTargetFolderPath.Text;

            if (tbMainTabs.SelectedTab == tabPage1)
            {
                settings.SelectionTab = 0;
            }
            else if (tbMainTabs.SelectedTab == tpHash)
            {
                settings.SelectionTab = 1;
            }

            if (rbCloudEndpoint.Checked)
            {
                settings.CloudEndpoint = true;
            }
            else
            {
                settings.CloudEndpoint = false;
            }

            if (rbCustom.Checked)
            {
                settings.Rule = "custom";
                settings.CustomRule = cbRuleListBox.Text;
            }
            else
            {
                MDRule mdRule = GetMDRule();
                settings.Rule = mdRule.GetRuleString();
            }

            settings.HashProcess = GetHashProcess();
            settings.HashSingle = tbHashSingle.Text;
            settings.HashFile = tbHashListFile.Text;
            settings.HashFileFolder = tbHashFileFolder.Text;

            settings.Serialize();
        }

        private MDHashProcess GetHashProcess()
        {
            MDHashProcess result = MDHashProcess.filefolder;

            if (rbHashSingle.Checked)
            {
                result = MDHashProcess.single;
            }
            else if (rbHashListFile.Checked)
            {
                result = MDHashProcess.listfile;
            }

            return result;
        }


        private MDFileAnalysis GetFileAnalyzer(string serverEndpoint, string apiKey)
        {
            MDFileAnalysis fileAnalyzer = new MDFileAnalysis(serverEndpoint, apiKey);
            return fileAnalyzer;
        }


        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///  File Worker Threads
        /// </summary>
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void FileScanWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                FileEnvironment fe = (FileEnvironment)e.Argument;
                MDFileAnalysis fileAnalyzer = GetFileAnalyzer(fe.ServerEndpoint, fe.Apikey);

                List<MDResponse> mdResponseList = fileAnalyzer.ProcessFolder(tbTargetFolderPath.Text, fe.Rule);
                e.Result = mdResponseList;
            }
            catch (Exception runningException)
            {
                MessageBox.Show(runningException.Message);
            }
        }

        private void FileScanWorker_Completed(object sender, RunWorkerCompletedEventArgs e)
        {
            List<MDResponse> responseList = e.Result as List<MDResponse>;
            UpdateStatusListView(lvFileScanResult, responseList);
            HideLoading(pbFileScanLoading);
        }

        private List<MDResponse> GetMDResponseListFromView(ListView listView)
        {
            List<MDResponse> responseList = new List<MDResponse>();

            foreach (ListViewItem item in listView.Items)
            {
                MDResponse mdResponse = item.Tag as MDResponse;
                responseList.Add(mdResponse);
            }

            return responseList;
        }


        private void FileStatusWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                FileEnvironment fe = (FileEnvironment)e.Argument;
                MDFileAnalysis fileAnalyzer = GetFileAnalyzer(fe.ServerEndpoint, fe.Apikey);

                List<MDResponse> mdResponseList = fileAnalyzer.UpdateStatusOnResponseList(fe.MdResponseList);
                e.Result = mdResponseList;

            }
            catch (Exception runningException)
            {
                MessageBox.Show(runningException.Message);
            }

        }

        private void FileStatusWorker_Completed(object sender, RunWorkerCompletedEventArgs e)
        {
            List<MDResponse> responseList = e.Result as List<MDResponse>;
            UpdateStatusListView(lvFileScanResult, responseList);
            HideLoading(pbFileScanLoading);
        }


        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///  Hash Worker Threads
        /// </summary>
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void HashLookupWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                int maxEntries = 100;
                HashEnvironment he = (HashEnvironment)e.Argument;
                MDFileAnalysis fileAnalyzer = GetFileAnalyzer(he.ServerEndpoint, he.Apikey);


                List<MDResponse> result = new List<MDResponse>();

                if (he.HashProcess == MDHashProcess.single)
                {
                    MDResponse singleResponse = fileAnalyzer.LookupHash(he.Single);
                    if (singleResponse != null)
                    {
                        result.Add(singleResponse);
                    }
                }
                else if (he.HashProcess == MDHashProcess.listfile)
                {
                    result = fileAnalyzer.LookupHashesFromListFile(he.ListFile, maxEntries);
                }
                else if (he.HashProcess == MDHashProcess.filefolder)
                {
                    result = fileAnalyzer.LookupHashesFileFolder(he.FileFolder, maxEntries);
                }

                e.Result = result;
            }
            catch (Exception runningException)
            {
                MessageBox.Show(runningException.Message);
            }
        }

        private void HashLookupWorker_Completed(object sender, RunWorkerCompletedEventArgs e)
        {
            List<MDResponse> responseList = e.Result as List<MDResponse>;
            HideLoading(pbHashLookupLoading);
            UpdateStatusListView(lvHashLookupResult, responseList);
        }

        private string GetServerAddress()
        {
            //
            // This is the Endpoint address to use for the cloud
            //
            string result = "https://api.metadefender.com/v4";

            if (rbOnPremEndpoint.Checked)
            {
                result = tbServerEndpoint.Text;
                result = "No Entry";
            }

            return result;
        }

        private void CheckConnectionInfo()
        {
            if (string.IsNullOrEmpty(tbApiKey.Text))
            {
                throw new Exception("The APIKey is required to run this request.");
            }

            string serverEndpoint = GetServerAddress();
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
                tpHash.Enabled = false;
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
                tpHash.Enabled = true;
            }
        }

        private void rbCustom_CheckedChanged(object sender, EventArgs e)
        {
            if (rbCustom.Checked == true)
            {
                cbRuleListBox.Enabled = true;
            }
            else
            {
                cbRuleListBox.Enabled = false;
            }
        }

        private MDRule GetMDRule()
        {
            MDRule result = new MDRule();

            if (rbCustom.Checked)
            {
                result.SetCustomRule(cbRuleListBox.Text);
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


        private FileEnvironment GetFileEnvironment()
        {
            FileEnvironment result = new FileEnvironment();

            CheckConnectionInfo();

            result.Rule = GetMDRule();
            result.ServerEndpoint = GetServerAddress();
            result.Apikey = tbApiKey.Text;
            result.MdResponseList = GetMDResponseListFromView(lvFileScanResult);

            SaveSettings();

            return result;
        }

        private HashEnvironment GetHashEnvironment()
        {
            HashEnvironment result = new HashEnvironment();

            CheckConnectionInfo();

            result.HashProcess = GetHashProcess();
            result.Single = tbHashSingle.Text;
            result.ListFile = tbHashListFile.Text;
            result.FileFolder = tbHashFileFolder.Text;

            result.ServerEndpoint = GetServerAddress();
            result.Apikey = tbApiKey.Text;

            SaveSettings();

            return result;
        }

        private void UpdateStatusListView(ListView destView, List<MDResponse> responseList)
        {
            destView.Items.Clear();

            foreach (MDResponse current in responseList)
            {
                ListViewItem item = new ListViewItem(current.FileName);
                item.SubItems.Add(current.Status);
                item.SubItems.Add(current.TotalEngines);
                item.SubItems.Add(current.Threat);
                item.SubItems.Add(current.ResponseType);
                item.Tag = current;

                destView.Items.Add(item);
            }
        }

        private void btnProcessFiles_Click(object sender, EventArgs e)
        {
            ShowLoading(pbFileScanLoading);

            FileEnvironment fe = GetFileEnvironment();
            fileScanWorker.RunWorkerAsync(fe);
        }

        private void btnBrowseFolder_Click(object sender, EventArgs e)
        {
            folderBrowserDialog1.ShowDialog();
            tbTargetFolderPath.Text = folderBrowserDialog1.SelectedPath;
        }

        private void btnRefreshStatus_Click(object sender, EventArgs e)
        {
            ShowLoading(pbFileScanLoading);

            FileEnvironment fe = GetFileEnvironment();
            fileStatusWorker.RunWorkerAsync(fe);
        }

        private void btnShowKey_Click(object sender, EventArgs e)
        {
            MessageBox.Show(tbApiKey.Text);
        }

        private void cbRules_DropDown(object sender, EventArgs e)
        {
            if (cbRuleListBox.Items.Count <= 1)
            {
                FileEnvironment fe = GetFileEnvironment();
                MDFileAnalysis fileAnalyzer = GetFileAnalyzer(fe.ServerEndpoint, fe.Apikey);
                MDRuleList ruleList = fileAnalyzer.GetRuleList();

                cbRuleListBox.Items.Clear();

                foreach (string rule in ruleList)
                {
                    cbRuleListBox.Items.Add(rule);
                }
            }
        }

        private void btnProcessHashes_Click(object sender, EventArgs e)
        {
            HashEnvironment hashEnvironment = GetHashEnvironment();

            ShowLoading(pbHashLookupLoading);
            hashLookupWorker.RunWorkerAsync(hashEnvironment);
        }


        private void HashRadioButtonChanged()
        {
            if (rbHashSingle.Checked)
            {
                tbHashSingle.Enabled = true;
                tbHashListFile.Enabled = false;
                tbHashFileFolder.Enabled = false;
                btnHashFileFolder.Enabled = false;
                btnHashListFile.Enabled = false;
            }
            else if (rbHashListFile.Checked)
            {
                tbHashSingle.Enabled = false;
                tbHashListFile.Enabled = true;
                tbHashFileFolder.Enabled = false;
                btnHashFileFolder.Enabled = false;
                btnHashListFile.Enabled = true;
            }
            else if (rbHashFileFolder.Checked)
            {
                tbHashSingle.Enabled = false;
                tbHashListFile.Enabled = false;
                tbHashFileFolder.Enabled = true;
                btnHashFileFolder.Enabled = true;
                btnHashListFile.Enabled = false;
            }

        }

        private void rbHashSingle_CheckedChanged(object sender, EventArgs e)
        {
            HashRadioButtonChanged();
        }

        private void rbHashListFile_CheckedChanged(object sender, EventArgs e)
        {
            HashRadioButtonChanged();
        }

        private void rbHashFileFolder_CheckedChanged(object sender, EventArgs e)
        {
            HashRadioButtonChanged();
        }

        private void btnHashFileFolder_Click(object sender, EventArgs e)
        {
            folderBrowserDialog1.ShowDialog();
            tbHashFileFolder.Text = folderBrowserDialog1.SelectedPath;
        }

        private void btnHashListFile_Click(object sender, EventArgs e)
        {
            openFileDialog1.ShowDialog();
            tbHashListFile.Text = openFileDialog1.FileName;
        }
    }
}

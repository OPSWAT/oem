namespace MetaDefenderFiles
{
    partial class MainForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            tbServerEndpoint = new TextBox();
            label1 = new Label();
            label2 = new Label();
            tbApiKey = new TextBox();
            btnShowKey = new Button();
            tbTargetFolderPath = new TextBox();
            label3 = new Label();
            btnBrowseFolder = new Button();
            rbCustom = new RadioButton();
            rbDLP = new RadioButton();
            rbUnarchive = new RadioButton();
            rbCDR = new RadioButton();
            rbSanitize = new RadioButton();
            rbMultiscan = new RadioButton();
            label4 = new Label();
            btnProcessFiles = new Button();
            label5 = new Label();
            rbCloudEndpoint = new RadioButton();
            rbOnPremEndpoint = new RadioButton();
            tbMainTabs = new TabControl();
            tabPage1 = new TabPage();
            cbRuleListBox = new ComboBox();
            label6 = new Label();
            pbLoading = new PictureBox();
            lvScanResult = new ScannerListView();
            columnHeader1 = new ColumnHeader();
            columnHeader2 = new ColumnHeader();
            columnHeader3 = new ColumnHeader();
            columnHeader4 = new ColumnHeader();
            btnRefreshStatus = new Button();
            tpHash = new TabPage();
            label7 = new Label();
            btnProcessHashes = new Button();
            btnHashFileFolder = new Button();
            btnHashListFile = new Button();
            tbHashFileFolder = new TextBox();
            tbHashListFile = new TextBox();
            rbHashFileFolder = new RadioButton();
            rbHashListFile = new RadioButton();
            rbHashSingle = new RadioButton();
            tbHashSingle = new TextBox();
            pictureBox1 = new PictureBox();
            scannerListView1 = new ScannerListView();
            columnHeader5 = new ColumnHeader();
            columnHeader6 = new ColumnHeader();
            columnHeader7 = new ColumnHeader();
            columnHeader8 = new ColumnHeader();
            folderBrowserDialog1 = new FolderBrowserDialog();
            tbMainTabs.SuspendLayout();
            tabPage1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)pbLoading).BeginInit();
            tpHash.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)pictureBox1).BeginInit();
            SuspendLayout();
            // 
            // tbServerEndpoint
            // 
            tbServerEndpoint.Enabled = false;
            tbServerEndpoint.Location = new Point(257, 11);
            tbServerEndpoint.Name = "tbServerEndpoint";
            tbServerEndpoint.Size = new Size(302, 23);
            tbServerEndpoint.TabIndex = 0;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(12, 15);
            label1.Name = "label1";
            label1.Size = new Size(93, 15);
            label1.TabIndex = 1;
            label1.Text = "Server Endpoint:";
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(565, 14);
            label2.Name = "label2";
            label2.Size = new Size(47, 15);
            label2.TabIndex = 2;
            label2.Text = "ApiKey:";
            // 
            // tbApiKey
            // 
            tbApiKey.Location = new Point(618, 11);
            tbApiKey.Name = "tbApiKey";
            tbApiKey.Size = new Size(195, 23);
            tbApiKey.TabIndex = 3;
            tbApiKey.UseSystemPasswordChar = true;
            // 
            // btnShowKey
            // 
            btnShowKey.Location = new Point(819, 11);
            btnShowKey.Name = "btnShowKey";
            btnShowKey.Size = new Size(75, 23);
            btnShowKey.TabIndex = 4;
            btnShowKey.Text = "Show Key";
            btnShowKey.UseVisualStyleBackColor = true;
            btnShowKey.Click += btnShowKey_Click;
            // 
            // tbTargetFolderPath
            // 
            tbTargetFolderPath.Location = new Point(114, 12);
            tbTargetFolderPath.Name = "tbTargetFolderPath";
            tbTargetFolderPath.Size = new Size(695, 23);
            tbTargetFolderPath.TabIndex = 5;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(8, 15);
            label3.Name = "label3";
            label3.Size = new Size(100, 15);
            label3.TabIndex = 6;
            label3.Text = "Folder to Process:";
            // 
            // btnBrowseFolder
            // 
            btnBrowseFolder.Location = new Point(815, 12);
            btnBrowseFolder.Name = "btnBrowseFolder";
            btnBrowseFolder.Size = new Size(75, 23);
            btnBrowseFolder.TabIndex = 7;
            btnBrowseFolder.Text = "Browse";
            btnBrowseFolder.UseVisualStyleBackColor = true;
            btnBrowseFolder.Click += btnBrowseFolder_Click;
            // 
            // rbCustom
            // 
            rbCustom.AutoSize = true;
            rbCustom.Location = new Point(383, 51);
            rbCustom.Name = "rbCustom";
            rbCustom.Size = new Size(70, 19);
            rbCustom.TabIndex = 26;
            rbCustom.Text = "Custom:";
            rbCustom.UseVisualStyleBackColor = true;
            rbCustom.CheckedChanged += rbCustom_CheckedChanged;
            // 
            // rbDLP
            // 
            rbDLP.AutoSize = true;
            rbDLP.Location = new Point(335, 51);
            rbDLP.Name = "rbDLP";
            rbDLP.Size = new Size(42, 19);
            rbDLP.TabIndex = 25;
            rbDLP.Text = "dlp";
            rbDLP.UseVisualStyleBackColor = true;
            // 
            // rbUnarchive
            // 
            rbUnarchive.AutoSize = true;
            rbUnarchive.Location = new Point(253, 51);
            rbUnarchive.Name = "rbUnarchive";
            rbUnarchive.Size = new Size(77, 19);
            rbUnarchive.TabIndex = 24;
            rbUnarchive.Text = "unarchive";
            rbUnarchive.UseVisualStyleBackColor = true;
            // 
            // rbCDR
            // 
            rbCDR.AutoSize = true;
            rbCDR.Location = new Point(205, 51);
            rbCDR.Name = "rbCDR";
            rbCDR.Size = new Size(42, 19);
            rbCDR.TabIndex = 23;
            rbCDR.Text = "cdr";
            rbCDR.UseVisualStyleBackColor = true;
            // 
            // rbSanitize
            // 
            rbSanitize.AutoSize = true;
            rbSanitize.Location = new Point(135, 51);
            rbSanitize.Name = "rbSanitize";
            rbSanitize.Size = new Size(64, 19);
            rbSanitize.TabIndex = 22;
            rbSanitize.Text = "sanitize";
            rbSanitize.UseVisualStyleBackColor = true;
            // 
            // rbMultiscan
            // 
            rbMultiscan.AutoSize = true;
            rbMultiscan.Checked = true;
            rbMultiscan.Location = new Point(52, 51);
            rbMultiscan.Name = "rbMultiscan";
            rbMultiscan.Size = new Size(77, 19);
            rbMultiscan.TabIndex = 21;
            rbMultiscan.TabStop = true;
            rbMultiscan.Text = "multiscan";
            rbMultiscan.UseVisualStyleBackColor = true;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new Point(8, 53);
            label4.Name = "label4";
            label4.Size = new Size(33, 15);
            label4.TabIndex = 27;
            label4.Text = "Rule:";
            // 
            // btnProcessFiles
            // 
            btnProcessFiles.Location = new Point(8, 99);
            btnProcessFiles.Name = "btnProcessFiles";
            btnProcessFiles.Size = new Size(100, 23);
            btnProcessFiles.TabIndex = 29;
            btnProcessFiles.Text = "Process Files";
            btnProcessFiles.UseVisualStyleBackColor = true;
            btnProcessFiles.Click += btnProcessFiles_Click;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new Point(8, 76);
            label5.Name = "label5";
            label5.Size = new Size(273, 15);
            label5.TabIndex = 30;
            label5.Text = "Note: Predefined rules are used with the Cloud API";
            // 
            // rbCloudEndpoint
            // 
            rbCloudEndpoint.AutoSize = true;
            rbCloudEndpoint.Checked = true;
            rbCloudEndpoint.Location = new Point(118, 13);
            rbCloudEndpoint.Name = "rbCloudEndpoint";
            rbCloudEndpoint.Size = new Size(57, 19);
            rbCloudEndpoint.TabIndex = 31;
            rbCloudEndpoint.TabStop = true;
            rbCloudEndpoint.Text = "Cloud";
            rbCloudEndpoint.UseVisualStyleBackColor = true;
            // 
            // rbOnPremEndpoint
            // 
            rbOnPremEndpoint.AutoSize = true;
            rbOnPremEndpoint.Location = new Point(181, 13);
            rbOnPremEndpoint.Name = "rbOnPremEndpoint";
            rbOnPremEndpoint.Size = new Size(72, 19);
            rbOnPremEndpoint.TabIndex = 32;
            rbOnPremEndpoint.Text = "OnPrem:";
            rbOnPremEndpoint.UseVisualStyleBackColor = true;
            rbOnPremEndpoint.CheckedChanged += rbOnPremEndpoint_CheckedChanged;
            // 
            // tbMainTabs
            // 
            tbMainTabs.Controls.Add(tabPage1);
            tbMainTabs.Controls.Add(tpHash);
            tbMainTabs.Location = new Point(12, 40);
            tbMainTabs.Name = "tbMainTabs";
            tbMainTabs.SelectedIndex = 0;
            tbMainTabs.Size = new Size(928, 479);
            tbMainTabs.TabIndex = 33;
            // 
            // tabPage1
            // 
            tabPage1.Controls.Add(cbRuleListBox);
            tabPage1.Controls.Add(label6);
            tabPage1.Controls.Add(pbLoading);
            tabPage1.Controls.Add(lvScanResult);
            tabPage1.Controls.Add(btnRefreshStatus);
            tabPage1.Controls.Add(tbTargetFolderPath);
            tabPage1.Controls.Add(label3);
            tabPage1.Controls.Add(label5);
            tabPage1.Controls.Add(btnBrowseFolder);
            tabPage1.Controls.Add(btnProcessFiles);
            tabPage1.Controls.Add(rbMultiscan);
            tabPage1.Controls.Add(rbSanitize);
            tabPage1.Controls.Add(label4);
            tabPage1.Controls.Add(rbCDR);
            tabPage1.Controls.Add(rbCustom);
            tabPage1.Controls.Add(rbUnarchive);
            tabPage1.Controls.Add(rbDLP);
            tabPage1.Location = new Point(4, 24);
            tabPage1.Name = "tabPage1";
            tabPage1.Padding = new Padding(3);
            tabPage1.Size = new Size(920, 451);
            tabPage1.TabIndex = 0;
            tabPage1.Text = "Folder";
            tabPage1.UseVisualStyleBackColor = true;
            // 
            // cbRuleListBox
            // 
            cbRuleListBox.FormattingEnabled = true;
            cbRuleListBox.Location = new Point(459, 50);
            cbRuleListBox.Name = "cbRuleListBox";
            cbRuleListBox.Size = new Size(350, 23);
            cbRuleListBox.TabIndex = 36;
            cbRuleListBox.DropDown += cbRules_DropDown;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new Point(701, 107);
            label6.Name = "label6";
            label6.Size = new Size(213, 15);
            label6.TabIndex = 35;
            label6.Text = "Double click on item to see JSON result";
            // 
            // pbLoading
            // 
            pbLoading.Image = Properties.Resources.Loading;
            pbLoading.Location = new Point(298, 172);
            pbLoading.Name = "pbLoading";
            pbLoading.Size = new Size(311, 259);
            pbLoading.SizeMode = PictureBoxSizeMode.StretchImage;
            pbLoading.TabIndex = 34;
            pbLoading.TabStop = false;
            // 
            // lvScanResult
            // 
            lvScanResult.Columns.AddRange(new ColumnHeader[] { columnHeader1, columnHeader2, columnHeader3, columnHeader4 });
            lvScanResult.FullRowSelect = true;
            lvScanResult.GridLines = true;
            lvScanResult.Location = new Point(8, 128);
            lvScanResult.MultiSelect = false;
            lvScanResult.Name = "lvScanResult";
            lvScanResult.OwnerDraw = true;
            lvScanResult.Size = new Size(906, 317);
            lvScanResult.TabIndex = 33;
            lvScanResult.UseCompatibleStateImageBehavior = false;
            lvScanResult.View = View.Details;
            // 
            // columnHeader1
            // 
            columnHeader1.Text = "File";
            columnHeader1.Width = 300;
            // 
            // columnHeader2
            // 
            columnHeader2.Text = "Status";
            columnHeader2.Width = 200;
            // 
            // columnHeader3
            // 
            columnHeader3.Text = "Engines";
            // 
            // columnHeader4
            // 
            columnHeader4.Text = "Scan Result";
            columnHeader4.Width = 150;
            // 
            // btnRefreshStatus
            // 
            btnRefreshStatus.Location = new Point(114, 99);
            btnRefreshStatus.Name = "btnRefreshStatus";
            btnRefreshStatus.Size = new Size(100, 23);
            btnRefreshStatus.TabIndex = 32;
            btnRefreshStatus.Text = "Refresh Status";
            btnRefreshStatus.UseVisualStyleBackColor = true;
            btnRefreshStatus.Click += btnRefreshStatus_Click;
            // 
            // tpHash
            // 
            tpHash.Controls.Add(label7);
            tpHash.Controls.Add(btnProcessHashes);
            tpHash.Controls.Add(btnHashFileFolder);
            tpHash.Controls.Add(btnHashListFile);
            tpHash.Controls.Add(tbHashFileFolder);
            tpHash.Controls.Add(tbHashListFile);
            tpHash.Controls.Add(rbHashFileFolder);
            tpHash.Controls.Add(rbHashListFile);
            tpHash.Controls.Add(rbHashSingle);
            tpHash.Controls.Add(tbHashSingle);
            tpHash.Controls.Add(pictureBox1);
            tpHash.Controls.Add(scannerListView1);
            tpHash.Location = new Point(4, 24);
            tpHash.Name = "tpHash";
            tpHash.Padding = new Padding(3);
            tpHash.Size = new Size(920, 451);
            tpHash.TabIndex = 1;
            tpHash.Text = "Hash";
            tpHash.UseVisualStyleBackColor = true;
            // 
            // label7
            // 
            label7.AutoSize = true;
            label7.Location = new Point(701, 107);
            label7.Name = "label7";
            label7.Size = new Size(213, 15);
            label7.TabIndex = 48;
            label7.Text = "Double click on item to see JSON result";
            // 
            // btnProcessHashes
            // 
            btnProcessHashes.Location = new Point(773, 23);
            btnProcessHashes.Name = "btnProcessHashes";
            btnProcessHashes.Size = new Size(118, 66);
            btnProcessHashes.TabIndex = 47;
            btnProcessHashes.Text = "Process";
            btnProcessHashes.UseVisualStyleBackColor = true;
            btnProcessHashes.Click += btnProcessHashes_Click;
            // 
            // btnHashFileFolder
            // 
            btnHashFileFolder.Location = new Point(536, 80);
            btnHashFileFolder.Name = "btnHashFileFolder";
            btnHashFileFolder.Size = new Size(75, 23);
            btnHashFileFolder.TabIndex = 46;
            btnHashFileFolder.Text = "Browse";
            btnHashFileFolder.UseVisualStyleBackColor = true;
            // 
            // btnHashListFile
            // 
            btnHashListFile.Location = new Point(536, 45);
            btnHashListFile.Name = "btnHashListFile";
            btnHashListFile.Size = new Size(75, 23);
            btnHashListFile.TabIndex = 45;
            btnHashListFile.Text = "Browse";
            btnHashListFile.UseVisualStyleBackColor = true;
            // 
            // tbHashFileFolder
            // 
            tbHashFileFolder.Location = new Point(101, 81);
            tbHashFileFolder.Name = "tbHashFileFolder";
            tbHashFileFolder.Size = new Size(428, 23);
            tbHashFileFolder.TabIndex = 44;
            // 
            // tbHashListFile
            // 
            tbHashListFile.Location = new Point(101, 46);
            tbHashListFile.Name = "tbHashListFile";
            tbHashListFile.Size = new Size(428, 23);
            tbHashListFile.TabIndex = 43;
            // 
            // rbHashFileFolder
            // 
            rbHashFileFolder.AutoSize = true;
            rbHashFileFolder.Location = new Point(13, 82);
            rbHashFileFolder.Name = "rbHashFileFolder";
            rbHashFileFolder.Size = new Size(82, 19);
            rbHashFileFolder.TabIndex = 42;
            rbHashFileFolder.TabStop = true;
            rbHashFileFolder.Text = "File Folder:";
            rbHashFileFolder.UseVisualStyleBackColor = true;
            rbHashFileFolder.CheckedChanged += rbHashFileFolder_CheckedChanged;
            // 
            // rbHashListFile
            // 
            rbHashListFile.AutoSize = true;
            rbHashListFile.Location = new Point(13, 47);
            rbHashListFile.Name = "rbHashListFile";
            rbHashListFile.Size = new Size(67, 19);
            rbHashListFile.TabIndex = 41;
            rbHashListFile.TabStop = true;
            rbHashListFile.Text = "List File:";
            rbHashListFile.UseVisualStyleBackColor = true;
            rbHashListFile.CheckedChanged += rbHashListFile_CheckedChanged;
            // 
            // rbHashSingle
            // 
            rbHashSingle.AutoSize = true;
            rbHashSingle.Location = new Point(13, 15);
            rbHashSingle.Name = "rbHashSingle";
            rbHashSingle.Size = new Size(55, 19);
            rbHashSingle.TabIndex = 40;
            rbHashSingle.TabStop = true;
            rbHashSingle.Text = "Hash:";
            rbHashSingle.UseVisualStyleBackColor = true;
            rbHashSingle.CheckedChanged += rbHashSingle_CheckedChanged;
            // 
            // tbHashSingle
            // 
            tbHashSingle.Location = new Point(101, 14);
            tbHashSingle.Name = "tbHashSingle";
            tbHashSingle.Size = new Size(428, 23);
            tbHashSingle.TabIndex = 37;
            // 
            // pictureBox1
            // 
            pictureBox1.Image = Properties.Resources.Loading;
            pictureBox1.Location = new Point(298, 172);
            pictureBox1.Name = "pictureBox1";
            pictureBox1.Size = new Size(311, 259);
            pictureBox1.SizeMode = PictureBoxSizeMode.StretchImage;
            pictureBox1.TabIndex = 36;
            pictureBox1.TabStop = false;
            pictureBox1.Visible = false;
            // 
            // scannerListView1
            // 
            scannerListView1.Columns.AddRange(new ColumnHeader[] { columnHeader5, columnHeader6, columnHeader7, columnHeader8 });
            scannerListView1.FullRowSelect = true;
            scannerListView1.GridLines = true;
            scannerListView1.Location = new Point(8, 125);
            scannerListView1.MultiSelect = false;
            scannerListView1.Name = "scannerListView1";
            scannerListView1.OwnerDraw = true;
            scannerListView1.Size = new Size(906, 320);
            scannerListView1.TabIndex = 35;
            scannerListView1.UseCompatibleStateImageBehavior = false;
            scannerListView1.View = View.Details;
            // 
            // columnHeader5
            // 
            columnHeader5.Text = "File";
            columnHeader5.Width = 300;
            // 
            // columnHeader6
            // 
            columnHeader6.Text = "Status";
            columnHeader6.Width = 200;
            // 
            // columnHeader7
            // 
            columnHeader7.Text = "Engines";
            // 
            // columnHeader8
            // 
            columnHeader8.Text = "Scan Result";
            columnHeader8.Width = 150;
            // 
            // MainForm
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(957, 531);
            Controls.Add(tbMainTabs);
            Controls.Add(rbOnPremEndpoint);
            Controls.Add(rbCloudEndpoint);
            Controls.Add(btnShowKey);
            Controls.Add(tbApiKey);
            Controls.Add(label2);
            Controls.Add(label1);
            Controls.Add(tbServerEndpoint);
            Name = "MainForm";
            Text = "MetaDefender File Analyzer";
            tbMainTabs.ResumeLayout(false);
            tabPage1.ResumeLayout(false);
            tabPage1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)pbLoading).EndInit();
            tpHash.ResumeLayout(false);
            tpHash.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)pictureBox1).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion
        private TextBox tbServerEndpoint;
        private Label label1;
        private Label label2;
        private TextBox tbApiKey;
        private Button btnShowKey;
        private TextBox tbTargetFolderPath;
        private Label label3;
        private Button btnBrowseFolder;
        private RadioButton rbCustom;
        private RadioButton rbDLP;
        private RadioButton rbUnarchive;
        private RadioButton rbCDR;
        private RadioButton rbSanitize;
        private RadioButton rbMultiscan;
        private Label label4;
        private Button btnProcessFiles;
        private Label label5;
        private RadioButton rbCloudEndpoint;
        private RadioButton rbOnPremEndpoint;
        private TabControl tbMainTabs;
        private TabPage tabPage1;
        private FolderBrowserDialog folderBrowserDialog1;
        private Button btnRefreshStatus;
        private ScannerListView lvScanResult;
        private ColumnHeader columnHeader1;
        private ColumnHeader columnHeader2;
        private ColumnHeader columnHeader3;
        private ColumnHeader columnHeader4;
        private PictureBox pbLoading;
        private Label label6;
        private ComboBox cbRuleListBox;
        private TabPage tpHash;
        private RadioButton rbHashFileFolder;
        private RadioButton rbHashListFile;
        private RadioButton rbHashSingle;
        private TextBox tbHashSingle;
        private PictureBox pictureBox1;
        private ScannerListView scannerListView1;
        private ColumnHeader columnHeader5;
        private ColumnHeader columnHeader6;
        private ColumnHeader columnHeader7;
        private ColumnHeader columnHeader8;
        private Button btnProcessHashes;
        private Button btnHashFileFolder;
        private Button btnHashListFile;
        private TextBox tbHashFileFolder;
        private TextBox tbHashListFile;
        private Label label7;
    }
}

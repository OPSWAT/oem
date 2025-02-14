///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

namespace MetaDefenderFiles
{
    internal class TextDialog : Form
    {
        private Panel panel1;
        private RichTextBox rtbText;
        private Button btnClose;

        private void InitializeComponent()
        {
            panel1 = new Panel();
            rtbText = new RichTextBox();
            btnClose = new Button();
            panel1.SuspendLayout();
            SuspendLayout();
            // 
            // panel1
            // 
            panel1.BorderStyle = BorderStyle.Fixed3D;
            panel1.Controls.Add(rtbText);
            panel1.Location = new System.Drawing.Point(12, 12);
            panel1.Name = "panel1";
            panel1.Padding = new Padding(10);
            panel1.Size = new System.Drawing.Size(1032, 555);
            panel1.TabIndex = 0;
            // 
            // rtbText
            // 
            rtbText.BackColor = System.Drawing.Color.FromArgb(255, 255, 255);
            rtbText.BorderStyle = BorderStyle.None;
            rtbText.Dock = DockStyle.Fill;
            rtbText.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Pixel);
            rtbText.ForeColor = System.Drawing.Color.FromArgb(222, 0, 0, 0);
            rtbText.Location = new System.Drawing.Point(10, 10);
            rtbText.Name = "rtbText";
            rtbText.Size = new System.Drawing.Size(1008, 531);
            rtbText.TabIndex = 0;
            rtbText.Text = "";
            // 
            // btnClose
            // 
            btnClose.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            btnClose.Location = new System.Drawing.Point(978, 576);
            btnClose.Margin = new Padding(4, 6, 4, 6);
            btnClose.Name = "btnClose";
            btnClose.Size = new System.Drawing.Size(66, 36);
            btnClose.TabIndex = 1;
            btnClose.Text = "Close";
            btnClose.UseVisualStyleBackColor = true;
            btnClose.Click += new EventHandler(btnClose_Click);
            // 
            // TextDialog
            // 
            ClientSize = new System.Drawing.Size(1056, 629);
            Controls.Add(btnClose);
            Controls.Add(panel1);
            Name = "TextDialog";
            panel1.ResumeLayout(false);
            ResumeLayout(false);
            PerformLayout();

        }

        public TextDialog(string text)
        {
            InitializeComponent();
            rtbText.Text = text;
        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            Close();
        }
    }
}

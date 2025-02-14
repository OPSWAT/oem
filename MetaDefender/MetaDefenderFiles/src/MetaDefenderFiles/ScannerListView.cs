﻿///////////////////////////////////////////////////////////////////////////////////////////////
///  Sample Code for MD File Analyzer
///  Reference Implementation using MetaDefender Server for analyzing files
///  
///  Created by Chris Seiler
///  OPSWAT OEM Solutions Architect
///////////////////////////////////////////////////////////////////////////////////////////////

using MDAdapter.MDClient;
using Newtonsoft.Json;

namespace MetaDefenderFiles
{

    public class ScannerListView : ListView
    {
        private ListViewColumnSorter lvwColumnSorter;
        public ScannerListView() : base()
        {
            this.OwnerDraw = true;
            this.DrawItem += new DrawListViewItemEventHandler(DrawItemEvent);
            this.DrawColumnHeader += new DrawListViewColumnHeaderEventHandler(DrawColumnHeaderEvent);
            this.DrawSubItem += new DrawListViewSubItemEventHandler(DrawSubItemEvent);

            lvwColumnSorter = new ListViewColumnSorter();
            this.ListViewItemSorter = lvwColumnSorter;
            this.ColumnClick += Lv_ColumnClick;
            this.FullRowSelect = true;
            this.GridLines = true;
            this.View = View.Details;
            this.MultiSelect = false;
            this.MouseDoubleClick += ScannerListView_MouseDoubleClick;

        }



        private void Lv_ColumnClick(object sender, ColumnClickEventArgs e)
        {
            // Determine if clicked column is already the column that is being sorted.
            if (e.Column == lvwColumnSorter.SortColumn)
            {
                // Reverse the current sort direction for this column.
                if (lvwColumnSorter.Order == SortOrder.Ascending)
                {
                    lvwColumnSorter.Order = SortOrder.Descending;
                }
                else
                {
                    lvwColumnSorter.Order = SortOrder.Ascending;
                }
            }
            else
            {
                // Set the column number that is to be sorted; default to ascending.
                lvwColumnSorter.SortColumn = e.Column;
                lvwColumnSorter.Order = SortOrder.Ascending;
            }

            // Perform the sort with these new sort options.
            this.Sort();

        }


        // Draws column headers.
        private void DrawColumnHeaderEvent(object sender,
            DrawListViewColumnHeaderEventArgs e)
        {
            using (StringFormat sf = new StringFormat())
            {
                // Store the column text alignment, letting it default
                // to Left if it has not been set to Center or Right.
                switch (e.Header.TextAlign)
                {
                    case HorizontalAlignment.Center:
                        sf.Alignment = StringAlignment.Center;
                        break;
                    case HorizontalAlignment.Right:
                        sf.Alignment = StringAlignment.Far;
                        break;
                }

                sf.LineAlignment = StringAlignment.Center;

                // Draw the background for an unselected item.
                using (SolidBrush brush =
                    new SolidBrush(System.Drawing.Color.LightBlue))
                {
                    e.Graphics.FillRectangle(brush, e.Bounds);
                }


                // Draw the header text.
                using (Font headerFont =
                            new Font("Helvetica", 10, FontStyle.Bold))
                {
                    e.Graphics.DrawString(e.Header.Text, headerFont,
                        Brushes.Black, e.Bounds, sf);
                }
            }
            return;
        }


        // Draws the backgrounds for entire ListView items.
        private void DrawItemEvent(object sender, DrawListViewItemEventArgs e)
        {
            e.DrawDefault = true;
        }

        // Draws the backgrounds for entire ListView items.
        private void DrawSubItemEvent(object sender, DrawListViewSubItemEventArgs e)
        {
            e.DrawDefault = true;
        }

              

        private static string FormatJson(string json)
        {
            string result = null;
            
            try
            {
                dynamic parsedJson = JsonConvert.DeserializeObject(json);
                result = JsonConvert.SerializeObject(parsedJson, Formatting.Indented);
            }
            catch(Exception)
            {
                result = json;
            }

            return result;
        }

        private void ScannerListView_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            if (this.SelectedItems.Count > 0)
            {
                MDResponse mdResponse = (MDResponse)this.SelectedItems[0].Tag;

                Settings settings = Settings.Deserialize();
                string jsonData = FormatJson(mdResponse.RawJson);

                TextDialog textDialog = new TextDialog(jsonData);
                textDialog.StartPosition = FormStartPosition.CenterParent;
                textDialog.ShowDialog();
            }
        }
    }
}

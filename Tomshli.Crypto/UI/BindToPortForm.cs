using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Tomshli.Crypto.UI
{
    public partial class BindToPortForm : Form
    {
        public int PortNumber
        {
            get { return (int)nbrPort.Value; }
            set { nbrPort.Value = value; }
        }
        public BindToPortForm()
        {
            InitializeComponent();
        }
    }
}

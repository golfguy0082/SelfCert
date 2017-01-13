using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Tomshli.Crypto.UI
{
    public partial class CertDetailsForm : Form
    {
        public StoreLocation CertStoreLocation { get; set; }
        public StoreName CertStoreName { get; set; }
        public X509Certificate2 Certificate { get; set; }

        public CertDetailsForm()
        {
            InitializeComponent();
        }

        private void CertDetailsForm_Load(object sender, EventArgs e)
        {
            txtStore.Text = string.Format("{0}/{1}", CertStoreLocation, CertStoreName);
            txtThumbprint.Text = Certificate.Thumbprint;

            RSACryptoServiceProvider privateKey = Certificate.PrivateKey as RSACryptoServiceProvider;
            if (null != privateKey)
            {
                string keyFile = privateKey.CspKeyContainerInfo.UniqueKeyContainerName;
                txtPrivateKeyFile.Text = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Crypto\RSA\MachineKeys"), keyFile);
            }
            else btnViewPrivateKeyFile.Enabled = false;
        }

        private void btnViewStore_Click(object sender, EventArgs e)
        {
            X509Store store = new X509Store(CertStoreName, CertStoreLocation);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2UI.SelectFromCollection(store.Certificates, txtStore.Text, "", X509SelectionFlag.SingleSelection);
        }

        private void btnViewCert_Click(object sender, EventArgs e)
        {
            X509Certificate2UI.DisplayCertificate(Certificate);
        }

        private void btnViewPrivateKeyFile_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Process.Start("explorer.exe", "/select," + txtPrivateKeyFile.Text);
        }

        private void btnBindToPort_Click(object sender, EventArgs e)
        {
            var dlg = new BindToPortForm();
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                BindToPortAndReportStatus(dlg.PortNumber);
            }
        }

        private void BindToPortAndReportStatus(int portNumber)
        {            
            var result = BindToPort(portNumber);
            if (result.Success)
                MessageBox.Show($"Bound certificate to port {portNumber}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
            {
                if (result.StdErrorOrOutput.Contains("Cannot create a file when that file already exists"))
                {
                    if (MessageBox.Show($"It looks like there's already a certificate bound to port {portNumber}.  Do you want to replace it?", "Conflict", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                    {
                        var removeBindingResult = RemoveBindingForPort(portNumber);
                        if (removeBindingResult.Success)
                        {
                            BindToPortAndReportStatus(portNumber);
                        }
                        else
                        {
                            MessageBox.Show($"Error: {removeBindingResult.StdErrorOrOutput}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
                else
                {
                    MessageBox.Show($"Error: {result.StdErrorOrOutput}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private CommandLineResult BindToPort(int portNumber)
        {
            var appId = Guid.NewGuid().ToString();
            var input = $"netsh http add sslcert ipport=0.0.0.0:{portNumber} certhash={Certificate.Thumbprint} appid={{{appId}}}";
            return ExecuteCommandline(input);            
        }

        private CommandLineResult RemoveBindingForPort(int portNumber)
        {
            var input = $"netsh http delete sslcert ipport=0.0.0.0:{portNumber}";
            return ExecuteCommandline(input);
        }        

        private static CommandLineResult ExecuteCommandline(string cmd)
        {
            int exitCode = -1;
            string stdErr = "";
            string stdOut = "";

            try
            {
                var args = $"/C {cmd}";
                var startInfo = new ProcessStartInfo()
                {
                    FileName = "CMD.exe",
                    Arguments = args,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true
                };
                var proc = Process.Start(startInfo);
                stdErr = proc.StandardError.ReadToEnd();
                stdOut = proc.StandardOutput.ReadToEnd();                
                proc.WaitForExit();
                exitCode = proc.ExitCode;                                               
            }
            catch (Exception ex)
            {
                stdErr = ex.Message;                
            }

            return new CommandLineResult(exitCode, stdOut, stdErr);
        }

        struct CommandLineResult
        {
            public bool Success
            {
                get { return ExitCode == 0; }
            }
            public int ExitCode { get; private set; }
            public string StdOut { get; private set; }
            public string StdError { get; private set; }
            /// <summary>
            /// Gets the stdError.  If stdError is null or empty, returns stdOut
            /// </summary>
            public string StdErrorOrOutput
            {
                get
                {
                    if (string.IsNullOrEmpty(StdError))
                        return StdOut;
                    return StdError;
                }
            }

            public CommandLineResult(int exit, string stdOut, string stdError)
            {
                ExitCode = exit;
                StdError = stdError;
                StdOut = stdOut;
            }
        }

        private static byte[] ConvertStringToBytes(string input)
        {

            MemoryStream stream = new MemoryStream();

            using (StreamWriter writer = new StreamWriter(stream))
            {
                writer.Write(input);
                writer.Flush();
            }

            return stream.ToArray();
        }
    }
}

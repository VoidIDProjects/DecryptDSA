using System.IO;
using System.Windows.Forms;

namespace Decrypt_DSA.Model
{
    public static class FileIO
    {
        public const string FILTER_MANIFEST = "Manifest |*.json|All files |*.*";
        public const string FILTER_MAFILE = "MAFILE |*.maFile|All files |*.*";

        public static string GetFilePath(string filter)
        {
            OpenFileDialog openFile = new OpenFileDialog();
            openFile.Filter = filter;
            var result = openFile.ShowDialog();
            if (result != DialogResult.OK) return null;
            else return openFile.FileName;
        }
        public static string GetDirectory()
        {
            string directory;

            using (var folder = new FolderBrowserDialog())
            {
                DialogResult result = folder.ShowDialog();
                if (result == DialogResult.OK && !string.IsNullOrWhiteSpace(folder.SelectedPath)) directory = folder.SelectedPath;
                else directory = null;
            }
            return directory;
        }
        public static string GetFileName(string path) => Path.GetFileName(path);
    }
}

using libdebug;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace PS4Saves
{
    public partial class Main : Form
    {
        PS4DBG ps4 = new PS4DBG();
        private int pid;
        private ulong stub;
        private ulong libSceUserServiceBase = 0x0;
        private ulong libSceSaveDataBase = 0x0;
        private ulong executableBase = 0x0;
        private ulong libSceLibcInternalBase = 0x0;
        private ulong GetSaveDirectoriesAddr = 0;
        private ulong GetUsersAddr = 0;
        private int user = 0x0;
        private string selectedGame = null;
        string mp = "";
        bool log = false;
        
        public Main()
        {
            InitializeComponent();
            Application.ApplicationExit += new EventHandler(this.OnApplicationExit);
            if (Directory.Exists(Directory.GetCurrentDirectory() + @"\payloads"))
            {
                string[] dirs = Directory.GetDirectories(Directory.GetCurrentDirectory() + @"\payloads", "*", SearchOption.TopDirectoryOnly);
                foreach (string dir in dirs)
                {
                    string fwDir = Path.GetFileName(dir);
                    fwCombo.Items.Add(fwDir);
                }
            }
            else
            {
                SetStatus("Missing payloads.");
            }            
            string[] args = Environment.GetCommandLineArgs();
            if (args.Length == 2 && args[1] == "-log")
            {
                log = true;
            }
            ipTextBox.Text = Properties.Settings.Default.ip;
            if (Properties.Settings.Default.defaultPayload.ToString() != "")
            {
                fwCombo.SelectedIndex = fwCombo.FindString(Properties.Settings.Default.defaultPayload);
            }            
            SetStatus("Waiting - Send Payload or just Connect if PS4Debug is already loaded on your PS4.");
        }
        public static string FormatSize(double size)
        {
            const long BytesInKilobytes = 1024;
            const long BytesInMegabytes = BytesInKilobytes * 1024;
            const long BytesInGigabytes = BytesInMegabytes * 1024;
            double value;
            string str;
            if (size < BytesInGigabytes)
            {
                value = size / BytesInMegabytes;
                str = "MB";
            }
            else
            {
                value = size /BytesInGigabytes;
                str = "GB";
            }
            return String.Format("{0:0.##} {1}", value, str);
        }
        private void sizeTrackBar_Scroll(object sender, EventArgs e)
        {
            sizeToolTip.SetToolTip(sizeTrackBar, FormatSize((double)(sizeTrackBar.Value * 32768)));
        }
        private void SetStatus(string msg)
        {
            statusLabel.Text = $"Status: {msg}";
        }
        private void WriteLog(string msg)
        {
            if(log)
            {
                var dateAndTime = DateTime.Now;
                var logStr = $"|{dateAndTime:MM/dd/yyyy} {dateAndTime:hh:mm:ss tt}|{msg}|";

                if (File.Exists(@"log.txt"))
                {
                    File.AppendAllText(@"log.txt",
                        $"{logStr}{Environment.NewLine}");
                }
                else
                {
                    using (var sw = File.CreateText(@"log.txt"))
                    {
                        sw.WriteLine(logStr);
                    }
                }

                Console.WriteLine(logStr);
            }
        }
        private void connectButton_Click(object sender, EventArgs e)
        {
            SetStatus("Connecting...");
            try
            {
                if (!checkIP(ipTextBox.Text))
                {
                    SetStatus("Invalid IP");
                    return;
                }
                ps4 = new PS4DBG(ipTextBox.Text);
                ps4.Connect();
                if (!ps4.IsConnected)
                {
                    throw new Exception();
                }
                SetStatus("Connected - Make sure the correct FW version is selected in payload dropdown and press Setup.");
                Properties.Settings.Default.ip = ipTextBox.Text;
                Properties.Settings.Default.Save();
            }
            catch
            {
                SetStatus("Failed to connect. Check IP and make sure PS4Debug payload is already loaded on the PS4.");
            }
        }

        private void setupButton_Click(object sender, EventArgs e)
        {
            statusLabel.Text = "Setting up...";
            string[] offsetsNew;

            if (!ps4.IsConnected)
            {
                SetStatus("Not connected to PS4.");
                return;
            }
            var pl = ps4.GetProcessList();
            var su = pl.FindProcess("SceShellUI");
            if (su == null)
            {
                SetStatus("Couldn't find SceShellUI");
                return;
            }
            pid = su.pid;
            var pm = ps4.GetProcessMaps(pid);
            var tmp = pm.FindEntry("libSceSaveData.sprx")?.start;
            if (tmp == null)
            {
                MessageBox.Show("savedata lib not found", "Error");
                return;
            }
            libSceSaveDataBase = (ulong)tmp;

            tmp = pm.FindEntry("libSceUserService.sprx")?.start;
            if (tmp == null)
            {
                MessageBox.Show("user service lib not found", "Error");
                return;
            }
            libSceUserServiceBase = (ulong)tmp;

            tmp = pm.FindEntry("executable")?.start;
            if (tmp == null)
            {
                MessageBox.Show("executable not found", "Error");
                return;
            }
            executableBase = (ulong)tmp;

            tmp = pm.FindEntry("libSceLibcInternal.sprx")?.start;
            if (tmp == null)
            {
                MessageBox.Show("libc not found", "Error");
                return;
            }
            libSceLibcInternalBase = (ulong)tmp;
            stub = pm.FindEntry("(NoName)clienthandler") == null ? ps4.InstallRPC(pid) : pm.FindEntry("(NoName)clienthandler").start;

            string selectedFw = fwCombo.Text.ToString();
            if (selectedFw == "")
            {
                SetStatus("Please select your FW from dropdown menu.");
                return;
            }

            var offsetspath = Directory.GetCurrentDirectory() + @"\payloads\" + selectedFw + @"\offsets";
            if (!File.Exists(offsetspath))
            {
                MessageBox.Show("offsets missing", "Error");
                return;
            }
            else
            {
                offsetsNew = File.ReadAllText(offsetspath).Split(',');
                if (offsetsNew.Length != 24)
                {
                    MessageBox.Show("offsets incorrect", "Error");
                    return;
                }
                else
                {
                    offsets.sceUserServiceGetInitialUser = Convert.ToUInt32(offsetsNew[17], 16);
                    offsets.sceUserServiceGetLoginUserIdList = Convert.ToUInt32(offsetsNew[18], 16);
                    offsets.sceUserServiceGetUserName = Convert.ToUInt32(offsetsNew[19], 16);
                    offsets.sceSaveDataMount = Convert.ToUInt32(offsetsNew[20], 16);
                    offsets.sceSaveDataUmount = Convert.ToUInt32(offsetsNew[21], 16);
                    offsets.sceSaveDataDirNameSearch = Convert.ToUInt32(offsetsNew[22], 16);
                    offsets.sceSaveDataInitialize3 = Convert.ToUInt32(offsetsNew[23], 16);

                    var ret = ps4.Call(pid, stub, libSceSaveDataBase + offsets.sceSaveDataInitialize3);
                    WriteLog($"sceSaveDataInitialize3 ret = 0x{ret:X}");
                    //PATCHES
                    //SAVEDATA LIBRARY PATCHES (libSceSaveData)
                    ps4.WriteMemory(pid, libSceSaveDataBase + Convert.ToUInt32(offsetsNew[0], 16), (byte)0x00); // 'sce_' patch
                    ps4.WriteMemory(pid, libSceSaveDataBase + Convert.ToUInt32(offsetsNew[1], 16), (byte)0x00); // 'sce_sdmemory' patch
                    ps4.WriteMemory(pid, libSceSaveDataBase + Convert.ToUInt32(offsetsNew[2], 16), (byte)0x30); // '_' patch
                    var l = ps4.GetProcessList();
                    var s = l.FindProcess("SceShellCore");
                    var m = ps4.GetProcessMaps(s.pid);
                    var ex = m.FindEntry("executable");

                    //SHELLCORE PATCHES (SceShellCore)
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[3], 16), (byte)0x00); // 'sce_sdmemory' patch
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[4], 16), new byte[] { 0x48, 0x31, 0xC0, 0xC3 }); //verify keystone patch
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[5], 16), new byte[] { 0x31, 0xC0, 0xC3 }); //transfer mount permission patch eg mount foreign saves with write permission
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[6], 16), new byte[] { 0x31, 0xC0, 0xC3 });//patch psn check to load saves saves foreign to current account
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[7], 16), new byte[] { 0x90, 0x90 }); // ^
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[8], 16), new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }); // something something patches... 
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[9], 16), new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }); // don't even remember doing this
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[10], 16), new byte[] { 0x90, 0x90 }); //nevah jump
                    ps4.WriteMemory(s.pid, ex.start + Convert.ToUInt32(offsetsNew[11], 16), new byte[] { 0x90, 0xE9 }); //always jump
                    //WRITE CUSTOM FUNCTIONS (libSceLibcInternal)
                    GetSaveDirectoriesAddr = ps4.AllocateMemory(pid, 0x8000);
                    ps4.WriteMemory(pid, GetSaveDirectoriesAddr, functions.GetSaveDirectories);
                    if (selectedFw == "5.05")
                    {
                        ps4.WriteMemory(pid, GetSaveDirectoriesAddr + 0x12, executableBase + Convert.ToUInt32(offsetsNew[12], 16)); //opendir
                        ps4.WriteMemory(pid, GetSaveDirectoriesAddr + 0x20, executableBase + Convert.ToUInt32(offsetsNew[13], 16)); //readdir
                        ps4.WriteMemory(pid, GetSaveDirectoriesAddr + 0x2E, executableBase + Convert.ToUInt32(offsetsNew[14], 16)); //closedir
                    }
                    else
                    {
                        ps4.WriteMemory(pid, GetSaveDirectoriesAddr + 0x12, libSceLibcInternalBase + Convert.ToUInt32(offsetsNew[12], 16)); //opendir
                        ps4.WriteMemory(pid, GetSaveDirectoriesAddr + 0x20, libSceLibcInternalBase + Convert.ToUInt32(offsetsNew[13], 16)); //readdir
                        ps4.WriteMemory(pid, GetSaveDirectoriesAddr + 0x2E, libSceLibcInternalBase + Convert.ToUInt32(offsetsNew[14], 16)); //closedir
                    }
                    ps4.WriteMemory(pid, GetSaveDirectoriesAddr + 0x3C, libSceLibcInternalBase + Convert.ToUInt32(offsetsNew[15], 16)); //strcpy

                    GetUsersAddr = GetSaveDirectoriesAddr + (uint)functions.GetSaveDirectories.Length + 0x20;
                    ps4.WriteMemory(pid, GetUsersAddr, functions.GetUsers);
                    ps4.WriteMemory(pid, GetUsersAddr + 0x15, libSceUserServiceBase + offsets.sceUserServiceGetLoginUserIdList);
                    ps4.WriteMemory(pid, GetUsersAddr + 0x23, libSceUserServiceBase + offsets.sceUserServiceGetUserName);
                    ps4.WriteMemory(pid, GetUsersAddr + 0x31, libSceLibcInternalBase + Convert.ToUInt32(offsetsNew[16], 16)); //strcpy

                    var users = GetUsers();
                    userComboBox.DataSource = users;
                    if (userComboBox.Items.Count == 0)
                    {
                        SetStatus("Setup failed. Make sure you have the correct FW selected in the dropdown menu and try again.");
                    }
                    else
                    {
                        SetStatus("Setup done. Select user and press 'Get Games' to scan for available games.");
                    }
                }
            }
        }

        private void searchButton_Click(object sender, EventArgs e)
        {

            if (!ps4.IsConnected)
            {
                SetStatus("Not connected to PS4.");
                return;
            }
            if (pid == 0)
            {
                SetStatus("Press 'Setup' first to get PS4 Users.");
                return;
            }
            if (selectedGame == null)
            {
                SetStatus("No game selected.");
                return;
            }
            var pm = ps4.GetProcessMaps(pid);
            if (pm.FindEntry("(NoName)clienthandler") == null)
            {
                SetStatus("RPC Stub Not Found");
                return;
            }
            var dirNameAddr = ps4.AllocateMemory(pid, Marshal.SizeOf(typeof(SceSaveDataDirName)) * 1024 + 0x10 + Marshal.SizeOf(typeof(SceSaveDataParam)) * 1024);
            var titleIdAddr = dirNameAddr + (uint) Marshal.SizeOf(typeof(SceSaveDataDirName)) * 1024;
            var paramAddr = titleIdAddr + 0x10;
            SceSaveDataDirNameSearchCond searchCond = new SceSaveDataDirNameSearchCond
            {
                userId = GetUser(),
                titleId = titleIdAddr
            };
            SceSaveDataDirNameSearchResult searchResult = new SceSaveDataDirNameSearchResult
            {
                dirNames = dirNameAddr,
                dirNamesNum = 1024,
                param = paramAddr,
            };
            ps4.WriteMemory(pid, titleIdAddr, selectedGame);
            dirsComboBox.DataSource = Find(searchCond, searchResult);
            ps4.FreeMemory(pid, dirNameAddr, Marshal.SizeOf(typeof(SceSaveDataDirName)) * 1024 + 0x10 + Marshal.SizeOf(typeof(SceSaveDataParam)) * 1024);
            if (dirsComboBox.Items.Count > 0)
            {
                SetStatus($"Found {dirsComboBox.Items.Count} save directories.");
            }
            else
            {
                SetStatus("Found 0 Save Directories.");
            }
        }

        private void mountButton_Click(object sender, EventArgs e)
        {
            if (!ps4.IsConnected)
            {
                SetStatus("Not connected to PS4.");
                return;
            }
            if (dirsComboBox.Items.Count == 0)
            {
                SetStatus("No save selected.");
                return;
            }
            if (selectedGame == null)
            {
                SetStatus("No game selected.");
                return;
            }
            var dirNameAddr = ps4.AllocateMemory(pid, Marshal.SizeOf(typeof(SceSaveDataDirName)) + 0x10 + 0x41);
            var titleIdAddr = dirNameAddr + (uint)Marshal.SizeOf(typeof(SceSaveDataDirName));
            var fingerprintAddr = titleIdAddr + 0x10;
            ps4.WriteMemory(pid, titleIdAddr, selectedGame);
            ps4.WriteMemory(pid, fingerprintAddr, "0000000000000000000000000000000000000000000000000000000000000000");
            SceSaveDataDirName dirName = new SceSaveDataDirName
            {
                data = dirsComboBox.Text
            };

            SceSaveDataMount mount = new SceSaveDataMount
            {
                userId = GetUser(),
                dirName = dirNameAddr,
                blocks = 32768,
                mountMode = 0x8 | 0x2,
                titleId = titleIdAddr,
                fingerprint = fingerprintAddr

            };
            SceSaveDataMountResult mountResult = new SceSaveDataMountResult
            {

            };
            ps4.WriteMemory(pid, dirNameAddr, dirName);
            mp = Mount(mount, mountResult);

            ps4.FreeMemory(pid, dirNameAddr, Marshal.SizeOf(typeof(SceSaveDataDirName)) + 0x10 + 0x41);
            if (mp != "")
            {
                SetStatus($"Save Mounted in {mp}.");
            }
            else
            {
                SetStatus("Mounting failed.");
            }
        }

        private void unmountButton_Click(object sender, EventArgs e)
        {
            if (!ps4.IsConnected)
            {
                SetStatus("Not connected to PS4.");
                return;
            }
            if (mp == "")
            {
                SetStatus("No save mounted.");
                return;
            }
            SceSaveDataMountPoint mountPoint = new SceSaveDataMountPoint
            {
                data = mp,
            };

            Unmount(mountPoint);
            mp = null;
            SetStatus("Save Unmounted.");
        }

        private void createButton_Click(object sender, EventArgs e)
        {
            if (!ps4.IsConnected)
            {
                SetStatus("Not connected to PS4.");
                return;
            }
            if (pid == 0)
            {
                SetStatus("Press 'Setup' first to get PS4 Users.");
                return;
            }
            if (nameTextBox.Text == "")
            {
                SetStatus("No save Name.");
                return;
            }
            if (selectedGame == null)
            {
                SetStatus("No game selected.");
                return;
            }
            var pm = ps4.GetProcessMaps(pid);
            if (pm.FindEntry("(NoName)clienthandler") == null)
            {
                SetStatus("RPC Stub Not Found");
                return;
            }

            var dirNameAddr = ps4.AllocateMemory(pid, Marshal.SizeOf(typeof(SceSaveDataDirName)) + 0x10 + 0x41);
            var titleIdAddr = dirNameAddr + (uint)Marshal.SizeOf(typeof(SceSaveDataDirName));
            var fingerprintAddr = titleIdAddr + 0x10;
            ps4.WriteMemory(pid, fingerprintAddr, "0000000000000000000000000000000000000000000000000000000000000000");
            ps4.WriteMemory(pid, titleIdAddr, selectedGame);
            SceSaveDataDirName dirName = new SceSaveDataDirName
            {
                data = nameTextBox.Text
            };

            SceSaveDataMount mount = new SceSaveDataMount
            {
                userId = GetUser(),
                dirName = dirNameAddr,
                blocks = (ulong) sizeTrackBar.Value,
                mountMode = 4 | 2 | 8,
                titleId = titleIdAddr,
                fingerprint = fingerprintAddr

            };
            SceSaveDataMountResult mountResult = new SceSaveDataMountResult
            {

            };
            ps4.WriteMemory(pid, dirNameAddr, dirName);
            var mp = Mount(mount, mountResult);
            ps4.FreeMemory(pid, dirNameAddr, Marshal.SizeOf(typeof(SceSaveDataDirName)) + 0x10 + 0x41);
            if (mp != "")
            {
                SetStatus("Save created.");
                SceSaveDataMountPoint mountPoint = new SceSaveDataMountPoint
                {
                    data = mp,
                };
                Unmount(mountPoint);
            }
            else
            {
                SetStatus("Save creation failed.");
            }
        }

        private int GetUser()
        {
            if(user != 0)
            {
                return user;
            }
            return InitialUser();          
        }

        private int InitialUser()
        {
            var bufferAddr = ps4.AllocateMemory(pid, sizeof(int));

            ps4.Call(pid, stub, libSceUserServiceBase + offsets.sceUserServiceGetInitialUser, bufferAddr);

            var id = ps4.ReadMemory<int>(pid, bufferAddr);

            ps4.FreeMemory(pid, bufferAddr, sizeof(int));

            return id;
        }

        private SearchEntry[] Find(SceSaveDataDirNameSearchCond searchCond, SceSaveDataDirNameSearchResult searchResult)
        {
            var searchCondAddr = ps4.AllocateMemory(pid, Marshal.SizeOf(typeof(SceSaveDataDirNameSearchCond)) + Marshal.SizeOf(typeof(SceSaveDataDirNameSearchResult)));
            var searchResultAddr = searchCondAddr + (uint)Marshal.SizeOf(typeof(SceSaveDataDirNameSearchCond));

            ps4.WriteMemory(pid, searchCondAddr, searchCond);
            ps4.WriteMemory(pid, searchResultAddr, searchResult);
            var ret = ps4.Call(pid, stub, libSceSaveDataBase + offsets.sceSaveDataDirNameSearch, searchCondAddr, searchResultAddr);
            WriteLog($"sceSaveDataDirNameSearch ret = 0x{ret:X}");
            if ( ret == 0)
            {
                searchResult = ps4.ReadMemory<SceSaveDataDirNameSearchResult>(pid, searchResultAddr);
                SearchEntry[] sEntries = new SearchEntry[searchResult.hitNum];
                var paramMemory = ps4.ReadMemory(pid, searchResult.param, (int)searchResult.hitNum * Marshal.SizeOf(typeof(SceSaveDataParam)));
                var dirNamesMemory = ps4.ReadMemory(pid, searchResult.dirNames, (int)searchResult.hitNum * 32);
                for (int i = 0; i < searchResult.hitNum; i++)
                {
                    SceSaveDataParam tmp = (SceSaveDataParam)PS4DBG.GetObjectFromBytes(PS4DBG.SubArray(paramMemory, i * Marshal.SizeOf(typeof(SceSaveDataParam)), Marshal.SizeOf(typeof(SceSaveDataParam))), typeof(SceSaveDataParam));
                    sEntries[i] = new SearchEntry
                    {
                        dirName = System.Text.Encoding.UTF8.GetString(PS4DBG.SubArray(dirNamesMemory, i * 32, 32)),
                        title = System.Text.Encoding.UTF8.GetString(tmp.title),
                        subtitle = System.Text.Encoding.UTF8.GetString(tmp.subTitle),
                        detail = System.Text.Encoding.UTF8.GetString(tmp.detail),
                        time = new DateTime(1970, 1, 1).ToLocalTime().AddSeconds(tmp.mtime).ToString(),
                    };
                }
                ps4.FreeMemory(pid, searchCondAddr, Marshal.SizeOf(typeof(SceSaveDataDirNameSearchCond)) + Marshal.SizeOf(typeof(SceSaveDataDirNameSearchResult)));
                return sEntries;
            }

            ps4.FreeMemory(pid, searchCondAddr, Marshal.SizeOf(typeof(SceSaveDataDirNameSearchCond)) + Marshal.SizeOf(typeof(SceSaveDataDirNameSearchResult)));

            return new SearchEntry[0];

        }

        private void Unmount(SceSaveDataMountPoint mountPoint)
        {
            var mountPointAddr = ps4.AllocateMemory(pid, Marshal.SizeOf(typeof(SceSaveDataMountPoint)));

            ps4.WriteMemory(pid, mountPointAddr, mountPoint);
            var ret = ps4.Call(pid, stub, libSceSaveDataBase + offsets.sceSaveDataUmount, mountPointAddr);
            WriteLog($"sceSaveDataUmount ret = 0x{ret:X}");
            ps4.FreeMemory(pid, mountPointAddr, Marshal.SizeOf(typeof(SceSaveDataMountPoint)));
            mp = null;
        }

        private string Mount(SceSaveDataMount mount, SceSaveDataMountResult mountResult)
        {
            var mountAddr = ps4.AllocateMemory(pid, Marshal.SizeOf(typeof(SceSaveDataMount)) + Marshal.SizeOf(typeof(SceSaveDataMountResult)));
            var mountResultAddr = mountAddr + (uint)Marshal.SizeOf(typeof(SceSaveDataMount));
            ps4.WriteMemory(pid, mountAddr, mount);
            ps4.WriteMemory(pid, mountResultAddr, mountResult);

            var ret = ps4.Call(pid, stub, libSceSaveDataBase + offsets.sceSaveDataMount, mountAddr, mountResultAddr);
            WriteLog($"sceSaveDataMount ret = 0x{ret:X}");
            if (ret == 0)
            {
                mountResult = ps4.ReadMemory<SceSaveDataMountResult>(pid, mountResultAddr);

                ps4.FreeMemory(pid, mountAddr, Marshal.SizeOf(typeof(SceSaveDataMount)) + Marshal.SizeOf(typeof(SceSaveDataMountResult)));

                return mountResult.mountPoint.data;
            }

            ps4.FreeMemory(pid, mountAddr, Marshal.SizeOf(typeof(SceSaveDataMount)) + Marshal.SizeOf(typeof(SceSaveDataMountResult)));

            return "";
        }

        class SearchEntry
        {
            public string dirName;
            public string title;
            public string subtitle;
            public string detail;
            public string time;
            public override string ToString()
            {
                return dirName;
            }
        }

        private void dirsComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            titleTextBox.Text = ((SearchEntry)dirsComboBox.SelectedItem).title;
            subtitleTextBox.Text = ((SearchEntry)dirsComboBox.SelectedItem).subtitle;
            detailsTextBox.Text = ((SearchEntry)dirsComboBox.SelectedItem).detail;
            dateTextBox.Text = ((SearchEntry)dirsComboBox.SelectedItem).time;
        }
        
        private void userComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            user = ((User)userComboBox.SelectedItem).id;
        }

        class User
        {
            public int id;
            public string name;

            public override string ToString()
            {
                return name;
            }
        }
        private string[] GetSaveDirectories()
        {
            var dirs = new List<string>();
            var mem = ps4.AllocateMemory(pid, 0x8000);
            var path = mem;
            var buffer = mem + 0x101;

            ps4.WriteMemory(pid, path, $"/user/home/{GetUser():x}/savedata/");
            var ret = (int)ps4.Call(pid, stub, GetSaveDirectoriesAddr, path, buffer);
            if (ret != -1 && ret != 0)
            {
                var bDirs = ps4.ReadMemory(pid, buffer, ret * 0x10);
                for (var i = 0; i < ret; i++)
                {
                    var sDir = System.Text.Encoding.UTF8.GetString(PS4DBG.SubArray(bDirs, i * 10, 9));
                    dirs.Add(sDir);
                }
            }
            ps4.FreeMemory(pid, mem, 0x8000);
            return dirs.ToArray();
        }

        private User[] GetUsers()
        {
            List<User> users = new List<User>();
            var mem = ps4.AllocateMemory(pid, 0x1);
            var ret = (int)ps4.Call(pid, stub, GetUsersAddr, mem);
            
            if (ret != -1 && ret != 0)
            {
                var buffer = ps4.ReadMemory(pid, mem, (21) * 4);
                for (int i = 0; i < 4; i++)
                {
                    var id = BitConverter.ToInt32(buffer, 21 * i);
                    if (id == 0)
                    {
                        continue;
                    }
                    var name = System.Text.Encoding.UTF8.GetString(PS4DBG.SubArray(buffer, i * 21 + 4, 16));
                    users.Add(new User { id = id, name = name });
                }
            }
            ps4.FreeMemory(pid, mem, 0x1);
            return users.ToArray();

        }
        public static bool checkIP(string IP)
        {
            return !string.IsNullOrEmpty(IP) && IPAddress.TryParse(IP, out _);
        }
        private void payloadButton_Click(object sender, EventArgs e)
        {
            try
            {
                if (!checkIP(ipTextBox.Text))
                {
                    SetStatus("Invalid IP.");
                    return;
                }
                if (fwCombo.SelectedIndex == -1)
                {
                    SetStatus("No payload selected.");
                    return;
                }
                else
                {
                    SetStatus("Sending payload");
                    string selectedFw = fwCombo.Text.ToString();
                    var payloadpath = Directory.GetCurrentDirectory() + @"\payloads\" + selectedFw + @"\ps4debug.bin";
                    Properties.Settings.Default.defaultPayload = selectedFw;
                    Properties.Settings.Default.Save();
                    if (File.Exists(payloadpath))
                    {
                        int ps4port = 9020;
                        if (selectedFw == "6.72")
                        {
                            ps4port = 9021;
                        }
                        using (FileStream stream = File.OpenRead(payloadpath))
                        {
                            var buffer = new byte[stream.Length];
                            stream.Read(buffer, 0, buffer.Length);
                            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                            IAsyncResult result = socket.BeginConnect(new IPEndPoint(IPAddress.Parse(ipTextBox.Text), ps4port), null, null);
                            var connected = result.AsyncWaitHandle.WaitOne(3000);
                            if (connected)
                            {
                               socket.Send(buffer, buffer.Length, SocketFlags.None);
                            }

                            SetStatus(connected ? "Payload sent. Press 'Connect'." : "Failed to connect.");
                            socket.Close();
                        }                       
                    }
                    else
                    {
                        SetStatus("Payload is missing from payload directory.");
                    }
                   
                }
            }
            catch
            {
                SetStatus("Sending payload failed.");
            }
        }

        private void getGamesButton_Click(object sender, EventArgs e)
        {
            if (!ps4.IsConnected)
            {
                SetStatus("Not connected to PS4.");
                return;
            }
            if (pid == 0)
            {
                SetStatus("Press 'Setup' first to get PS4 Users.");
                return;
            }
            var pm = ps4.GetProcessMaps(pid);
            if (pm.FindEntry("(NoName)clienthandler") == null)
            {
                SetStatus("RPC Stub Not Found");
                return;
            }
            var dirs = GetSaveDirectories();
            gamesComboBox.DataSource = dirs;
            SetStatus(gamesComboBox.Items.Count+" games found. Select a game and press 'Search' to scan for available saves.");
        }

        private void gamesComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            selectedGame = (string)gamesComboBox.SelectedItem;
        }

        private void OnApplicationExit(object sender, EventArgs e)
        {
            if (!ps4.IsConnected)
            {
                return;
            }
            if (mp == "")
            {
                return;
            }
            SceSaveDataMountPoint mountPoint = new SceSaveDataMountPoint
            {
                data = mp,
            };

            Unmount(mountPoint);
            mp = null;
        }
    }
}

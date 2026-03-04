|--------------------------------------------------(0x01)----------(readme)--|

This is the README file for ioFTPD.

ioFTPD is a secure, high performance, scalable ftp server with features
designed for enterprise use.


|--------------------------------------------------(0x02)-----------(legal)--|

ioFTPD is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

ioFTPD is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ioFTPD; see the file COPYING.  if not, write to the
Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
MA 02110-1301, USA.


|--------------------------------------------------(0x03)---------(install)--|

#### Simple Installation (advanced is later in file)

1) Extract the zip file to C:\

2) Unless you have a VERY static IP address I suggest you setup a dynamic
   DNS resolver for your IP address.  www.no-ip.com is free and allows
   you to choose from a variety of domains like .myftp.org, etc.

3) Modify the ioFTPD\etc\default.vfs file to setup the root directory and
   the rest of the virtual file system.  I've included complete directions
   in the file itself.
   NOTE: Don't be a moron and let notepad or something save the text file
         as default.vfs.txt!

4) If you are behind a router or otherwise need to forward ports the default
   configuration uses ports 5420 as the FTP port and 5421-5450 as the PASV
   port range.  You WILL need to forward them in your router/firewall!
   Check out your vendors website for information on how to do this.  The
   ports are configurable via ioFTPD.ini if you must change them.

5) Check out the rest of the ioFTPD\system\ioFTPD.ini file.  ioFTPD is very
   flexible and I've commented the file FAR more than the original version,
   but it's not for the faint of heart as it doesn't report bad
   configurations...

6) Click on ioFTPD-START.exe to start the ioFTPD server and after a delay to
   start ioGui2 as the visual interface.  ioFTPD has no built-in user
   interface.  You can also start ioFTPD\system\ioFTPD.exe manually without
   a GUI.

7) IMPORTANT: If you get the following popup error dialog:  "This application
   has failed to start because the application configuration is incorrect.
   Reinstalling the application may fix this problem."  Then you need to
   install the Visual C++ 2015-2022 Redistributable (x86) from Microsoft:
     https://aka.ms/vc14/vc_redist.x86.exe
   The file is called vc_redist.x86.exe.  Run it and then run Windows Update
   to make sure you have the latest patches.

   NOTE: v7.9.0 introduced new DLL names.  libssl.dll and libcrypto.dll
   replace the old libeay32.dll and ssleay32.dll (OpenSSL 3.6.1), and
   tcl90.dll replaces tcl85t.dll (Tcl 9.0).  If upgrading from a release
   prior to v7.9.0 you MUST remove the old DLLs from the \system directory
   before running the new build, otherwise the wrong library may be loaded.

8) ioGui2 is setup to login using the default username/password/port for the
   master account (ioFTPD/ioFTPD/5420) which we will now change.  If the
   ioFTPD entry under sitename contains a red X on it then it didn't connect.
   This is most likely caused by your firewall denying ioFTPD.exe the ability
   to listen for connections.  Just go ahead and authorize it.  After doing
   that you may need to restart the server, so kill the ioFTPD.exe process
   in the task manager, manually restart the server by running
   ioFTPD\system\ioFTPD.exe and then double clicking on ioFTPD under Sitename
   in ioGUI to see if it connects.  If successful goto the text entry field
   at the bottom of the CONSOLE tab and enter the command:
     SITE PASSWD <new password>

9) Now right click on the ioFTPD site on the left hand side and select
   the "Edit..." option.  Update the password you just set for the master
   account.

10) To automatically start the server each time you boot up you can create
    a link to the ioFTPD-Start.exe file and place it in your Startup folder,
    or you can install ioFTPD.exe as a service (see
    system\ServiceInstall-README.txt).

11) To enable SSL encrypted connections to the server.  From ioGUI's console
    enter the following command:
      SITE MAKECERT
    You should see a message saying a new cert was created and installed on
    the machine.  You can use SSL logins now.

12) You don't have to shutdown ioFTPD when rebooting or turning the computer
    off, but if you want to shut it down don't kill it via Task Manager while
    users are logged on.
    Instead issue
      site shutdown       [ gives online users a grace period to logout]
          or
      site shutdown now
    command from the text box of the console tab in ioGUI.



### User Accounts

1) You can create accounts via ioGUI or using the site commands from any
   FTP client.  From the console text box in ioGUI use the:
     SITE ADDUSER <username> <password> <ident@hostname>
   command (don't forget the last part, use *@* if you don't care), or
   from the USER tab make sure you:
     A) Make the user part of the "NoGroup" group.
     B) Set the users RATIO to 0 so they can leech
     C) Add at least one entry to the Ident/IP list, use *@* if you don't
        care, but you must set it.

2) ioFTPD uses "user flags" to control access to certain actions (each
   and every action is controlled via permissions in ioFTPD.ini).
   Here's a brief summary of the builtin ones:
     'M' - MASTER
     'V' - VFS ADMINISTRATOR
     'G' - GROUP ADMIN RIGHTS
     'F' - FXP DENIED (DOWNLOAD)
     'f' - FXP DENIED (UPLOAD)
     'L' - SKIP USER LIMIT PER SERVICE
     'A' - ANONYMOUS
   By convention the following are used:
     '1' - Power Admin - can do most things Master can do such as add/delete
           or modify users, groups, vfs, etc.  Think shaz here.
     '3' - Full user - can upload/download/delete stuff in the filesystem
           subject to file/dir permissions.

   The "site adduser" and ioGUI give out the 3 flag by default which should
   be fine for regular users.  Change the 3 to Z or just leave it blank if
   you want someone to just be able to download.
   "site adduser" drops people by default in the "NoGroup" group.


### TROUBLESHOOTING

1) If ioFTPD appears to not start or you can't connect to it, first open
   up the Task Manager and see if ioFTPD is running.  Make sure you haven't
   started TWO copies from the same directory as they'll just interfere with
   each other.  In this case use ioGUI to connect to one of them, issue the
   "site shutdown" command, reconnect and you should get the other one and
   shut it down as well, and then start up a fresh copy.

2) Make sure you have setup the root dir listed in default.vfs.  Nobody
   can login until the FTP server knows the default directory!

3) Check the \ioFTPD\logs directory and look at the timestamps for which
   files might include new error information.  Read the log files for more
   information about the error condition.  In particular the logs\Error.log
   file should explain why a user can't login.

4) If the ioFTPD.exe process is crashing, check the \ioFTPD\system directory
   for a file named crash_YYYYMMDD_HHMMSS.dmp (e.g. crash_20260101_143022.dmp).
   This is a Windows minidump file that can be opened in WinDbg or Visual
   Studio for analysis.  Report this problem along with the .dmp file to
   the forum.

5) Firewall settings correct?


|--------------------------------------------------(0x04)-----(long-paths)--|

### Long-Path Support (v7.10.0+)

ioFTPD can handle paths longer than the Windows legacy 260-character limit
(MAX_PATH) on Windows 10 build 14393 / Server 2016 and later.

Requirements (all three must be present):
  1. Windows 10 build 14393 (v1607) or Server 2016 or later.
  2. Registry key set to 1:
       HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled
  3. ioFTPD.exe manifest declares longPathAware (embedded at build time).

INI configuration:
  [FTP]
  Long_Path_Support = Auto   ; Auto (default), On, or Off

Long-path behavior by storage backend:

  Local NTFS   — fully supported for all FTP operations.
  Mapped drive — same as local NTFS (Windows resolves UNC before ioFTPD sees it).
  UNC / SMB    — partially supported.  SMB servers impose their own path limits
                 (typically 1-4 KB depending on server), often failing before NTFS
                 would.  Affected commands: STOR, APPE, RETR, RNFR/RNTO, directory
                 recursion.  Reparse point (junction) operations are not supported
                 over SMB.

When a path is too long for NTFS or the SMB server, ioFTPD returns:
  550 <path>: Path too long for NTFS.

This applies regardless of which specific Windows error code was returned
internally (ERROR_FILENAME_EXCED_RANGE, ERROR_INVALID_NAME,
ERROR_PATH_NOT_FOUND, or ERROR_FILE_NOT_FOUND for very long paths).


|--------------------------------------------------(0x05)---------(support)--|

The preferred place for support, bug reporting, script info, source code, and
general help is via the ioFTPD user's and developer's forum:
  http://www.ioftpd.com or www.flashfxp.com/forum

the original source code for ioFTPD v5.x is available on sourceforge, 
  http://ioftpd.sourceforge.net/

the latest release and the v6.x source code (maintained by Yil) can be
gotten via the forum above.

|---------------------------------------------------------------------(eof)--|

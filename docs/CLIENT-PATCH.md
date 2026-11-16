# Patching the client (optional)

[← Back to the README](../README.md)

Everything else in RCEGuard watches the client from outside. This section is about the client file itself,
and it is the only place where RCEGuard offers to change it. **RCEGuard never does that by
itself:** the service, the tray application and `install.ps1` only read the header of the file.

**What it is about.** The 3.3.5a client (`Wow.exe`, build 12340) has one small section,
`.zdata`: 4096 bytes, empty in the file, writable **and** executable, and at the same address
at every start because the client has no address randomisation. Whatever gets written there can
be run. The well-known [RCEPatcher](https://github.com/stoneharry/RCEPatcher) takes the execute
right away from that section by changing one byte in the header of the file; according to its
authors a patched client crashes when a server tries the remote code exploit.

**Where RCEGuard tells you.** If the client has such a section, `install.ps1` says so once at
its end, and

```powershell
& 'C:\Program Files\RCEGuard\RCEGuard.Service.exe' --check-client
```

prints it for every profile whenever you ask. None of this changes anything. There is no
standing warning in the log or in the tray application: on a server where the section is
needed for logging in (see the real try below) it would be a warning nobody can act on.

**Changing the file** is done by `scripts\patch-client.ps1`, which you start yourself. It makes
the same one-byte change, but first checks that the file is what it expects (a 32-bit program
with exactly one writable and executable section, named `.zdata`, that is empty in the file and
that the program neither starts in nor keeps a table in), and it can undo the change. It needs
no administrator rights if you may write to the game folder.

```powershell
.\scripts\patch-client.ps1 -ClientPath 'D:\Games\Warmane\Wow.exe' -CheckOnly
```

1. `-CheckOnly` shows the sections and says whether the script would change the file.
2. Without a switch it writes a copy `Wow_patched.exe` next to the client and leaves the
   original alone. Start the copy and go as far as the login screen: that shows whether the
   client still runs, without an account being involved.
3. `-InPlace` changes the file itself (the client must not be running) and keeps the unchanged
   file as `Wow.exe.unpatched`. Launchers and RCEGuard go on using the same path.
4. `-Undo` gives the execute right back; the file is then byte for byte what it was.

**One real try (2026-11-16, one server, build 12340).** The patched copy started and showed
the login screen. Right after the password was entered it crashed, in two of two tries, with
`ACCESS_VIOLATION at 00DD1000`: the first address of `.zdata`, where Windows now refuses to run
code. The crash report of the client shows the way there: code of the client called code that
had been loaded at run time and belongs to no file, and that code called into `.zdata`. So on
that server something that arrives at login runs code in this very section as a matter of
course. The patch cannot tell wanted code from unwanted code there: **with such a server a
patched client cannot log in.** It also shows what the section is used for in practice. Try the
copy first, as described above, before you change the client for good.

**What nobody here can tell you:**

- whether the change stops a particular exploit. RCEGuard contains no exploit and has not
  tested that; it is what the authors of the patcher say, and it fits what the file shows.
- whether a server minds a client file that was changed. Decide yourself whether to log in
  with it, and with which account.
- whether a client that is not build 12340 behaves the same. The script refuses a file that
  does not have the layout described above.

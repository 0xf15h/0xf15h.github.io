---
layout: post
title:  Reverse Engineering Old Pegasus Android LPEs
---

Earlier today, vx-underground published Android Pegasus samples to their archive [[link]](https://twitter.com/vxunderground/status/1418207502974525441?s=20). The ZIP they provided contained three samples:

`d257cfde7599f4e20ee08a62053e6b3b936c87d373e6805f0e0c65f1d39ec320`

- First seen in the wild: 2013-05-15
- First VT submission: 2013-11-15
- [VirusTotal](https://www.virustotal.com/gui/file/d257cfde7599f4e20ee08a62053e6b3b936c87d373e6805f0e0c65f1d39ec320/details)

`144778790d4a43a1d93dff6b660a6acb3a6d37a19e6a6f0a6bf1ef47e919648e`

- First seen in the wild: 2017-07-01
- First VT submission: 2016-03-18
- [VirusTotal](https://www.virustotal.com/gui/file/144778790d4a43a1d93dff6b660a6acb3a6d37a19e6a6f0a6bf1ef47e919648e/details)

`bd8cda80aaee3e4a17e9967a1c062ac5c8e4aefd7eaa3362f54044c2c94db52a`

- First seen in the wild: 2020-01-14
- First VT submission: 2018-11-11
- [VirusTotal](https://www.virustotal.com/gui/file/bd8cda80aaee3e4a17e9967a1c062ac5c8e4aefd7eaa3362f54044c2c94db52a/details)

I decided to look at the last sample because it's the most recent. The `/res/raw/sucopier` caught my interest because the `su` prefix denotes it's probably a privilege escalation exploit.

The program expects two command line arguments: `sucopier <source_file_path> <destination_file_path>`. It gets the path to the current executable from reading the procfs symlink at `/proc/self/exe`. If its current UID is not root, it calls a function that iteratively attempts up to six LPEs in the `g_exploits` table (yes, they left the symbol in). I reverse engineered most the exploit structure they used in each entry in the `g_exploits` table:

```C
struct exploit
{
    char *name;
    char *dev_file;
    int   mmap_fd;
    int   unk_1;
    int   unk_2;
    int   mmap_offset;
    int   mmap_len;
    int   system_ram_offset_index;
    int   unk_3;
    int   unk_4;
    int   unk_5;
    void (*trigger)(struct exploit *);
    void (*cleanup)(struct exploit *);
};
```

The six exploits are all abusing mmap bounds checks to access kernel memory. The exploits are called in the following order:

- Sam ("/dev/exynos-mem")
- Gimli ("/dev/DspBridge")
- Merry ("/dev/s5p-smem")
- Frodo ("/dev/exynos-mem")
- Aragon ("/dev/video1")
- Legolas ("/dev/graphics/fb5")

I thought this was a unique naming convention and after a bit of Googling it turns out to be Framaroot, a root tool from Android 4. Azimuth Security did a blog post discussing a few of these exploits in 2013 [[link]](http://blog.azimuthsecurity.com/2013/02/re-visiting-exynos-memory-mapping-bug.html)[[archive]](https://web.archive.org/web/20130221032723/blog.azimuthsecurity.com/2013/02/re-visiting-exynos-memory-mapping-bug.html). The blog post was really helpful because I couldn't find source for most of the drivers because they're so old. This also implies that this malware is not from 2018; VirusTotal is struggling to keep up with Pegasus. After poking around `libframalib.so`, I realized that `sucopier` uses the exact same naming convention and exploit structure, except it's surrounded by completely different code, compiled in a different way. Framaroot has always been shipped as an APK with all of the exploits in one monolithic library called `libframalib.so`. This giant library entangles a bunch of SuperSU features around the LPEs, making them extremely difficult to objcopy out to repurpose. The next logical conclusion was that NSO Group just reverse engineered Framaroot and reused the exploit. If this is the case, I don't know why they chose to include the Lord of the Rings naming convention in plaintext and remove the `exploit->dev_file` XOR encoding that Framaroot used:

![](/assets/pegasus/dev_file_decode.png)

It's also possible that NSO Group had Framaroot source, but who knows ¯\\_(ツ)_/¯


After the LPE, it returns the the function and checks its UID is root to verify the exploit was successful. If the program successfully rooted itself, it uses the path from `/proc/self/exe` to execute itself again with `system(path_to_current_exe, src_file, dst_file)`. I'd assume that they felt the need create a new process in case of any memory corruption artifacts, but I'm not sure.

The `sucopier` binary gets to the initial UID check and this time succeeds. It then mount the YAFFS2 filesystem at `/dev/block/mtdblock3` block as `/system`. These values are hardcoded which makes me believe this binary was compiled to target a specific device. If they were trying to make this even slightly robust, they could parse the `/dev/block/platform/*/by-name/` symlinks instead. Then the file from the source command line argument is copied to the destination command line argument. The destination file's ownership is set to root for both UID and GID and the mode is set to `r-x r-x r-x`. It then remounts the previous `/system` with the `MS_RDONLY` flag set so it's readonly. Finally it sleeps for 10 seconds and exits. This is extremely inefficient because the tool limits callers to a single file copy per execution which ends in a 10 second sleep on success. Hopefully NSO doesn't plan on coping too many files into `/system`.

I was really bummed that this wasn't even a semi-recent sample from 2018. If anyone is willing to share some more modern Pegasus samples, please let me know!

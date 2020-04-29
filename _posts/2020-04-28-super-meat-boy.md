---
layout: post
title:  Hidden Cheat Code within Super Meat Boy's Save File
---

This weekend I got stuck on a level in Super Meat Boy and needed to take a break so I decided to poke around the binary
for a bit. I started with a bit of recon by checking out some of the files that shipped with the binary.

The first file I looked at was locdb.txt, which is just a text file containing the game's strings in various languages.
Each string and its translations were on their own line with each translated string separated by a tab character. This
wasn't very interesting so I kept looking around for something better.

The UserData/savegame.dat file caught my eye and got me thinking... What if I could just modify the save file to tell
the game I've completed the level?! With this goal in mind I loaded up the binary in Ghidra and got to work.

Super Meat Boy uses a custom game engine, called Tommunism, which is written in C++. The game engine is statically
linked with the game so we don't get any helpful import or export function signatures. To make matters worse, there
aren't too many string references in the binary because they're stored in locdb.txt and loaded at runtime. I quickly
found myself getting overwhelmed by deep inheritance trees because I wasn't just reversing a game, I was reversing a
game engine too! A dynamic analysis approach was definitely needed.

There was a string reference to savegame.dat that I traced to a WinAPI CreateFileA call. With x64dbg, I set a breakpoint
on CreateFileA to get the savegame.dat file's HANDLE. The breakpoint was triggered after pressing start on the title
screen when you start the game. I then set a breakpoint for the WinAPI ReadFile function and saw the address of the
buffer that the data was read into. From there, I set a memory access breakpoint on the buffer so it would break when
the buffer was getting parsed. It was triggered in a memcpy, but the stacktrace helped me pinpoint the functions of
interest. Again, I was greeted with inheritance hierarchy hell but I was able to make sense of it with dynamic analysis.
The first DWORD of the savegame.dat file was compared to 0x31304653 ("10FS" in ASCII). If they were equal, it would skip
over a huge code block that continued parsing the save file. I overwrote the first DWORD of my save file with the
hard coded value and restarted my client. It unlocked chapters one, two, four, six, and seven with every level in the
chapter unlocked with an A+ rating. The Dark World levels were completed too.

![Unlocked worlds](https://i.imgur.com/Nsn4QAS.png)

![Unlocked levels](https://i.imgur.com/2K4QvYf.png)

This cheat code was probably just used for testing during development and accidentally made it into production. It could
easily be patched out by the developers if they wanted to, but I don't see why they'd bother since it's a single player
game. Anyway I ended up restoring my old save file to avoid ruining the game. Hopefully this time I can beat the level
without resorting to cheating.

# OverTheWire - Leviathan

[![OverTheWire: Leviathan](https://img.shields.io/badge/OverTheWire-Leviathan-white)](https://overthewire.org/wargames/leviathan/)

<details>
<summary><b>Table of Contents</b></summary>

- [Introduction](#introduction)
- [Level 0](#level-0)
- [Level 1](#level-1)
- [Level 2](#level-2)
- [Level 3](#level-3)
- [Level 4](#level-4)
- [Level 5](#level-5)
- [Level 6](#level-6)
- [Level 7](#level-7)

</details>

## Introduction

The `Leviathan` wargame is a beginner series based around navigating the Linux command line, similar to the [Bandit](Bandit.md) series.

**Connecting to Leviathan**

```
Leviathan’s levels are called leviathan0, leviathan1, ... etc. and can be accessed on leviathan.labs.overthewire.org through SSH on port 2223.

To login to the first level use:

Username: leviathan0
Password: leviathan0
```

## Level 0

After logging in to `leviathan0`, we do a `ls -la`:

```bash
$ ls -la
total 24
drwxr-xr-x  3 root       root       4096 Aug 26  2019 .
drwxr-xr-x 10 root       root       4096 Aug 26  2019 ..
drwxr-x---  2 leviathan1 leviathan0 4096 Aug 26  2019 .backup
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root        675 May 15  2017 .profile
```

We notice a folder created by `leviathan1` named `.backup`, which contains a `bookmarks.html` file:

```bash
$ ls -la .backup
total 140
drwxr-x--- 2 leviathan1 leviathan0   4096 Aug 26  2019 .
drwxr-xr-x 3 root       root         4096 Aug 26  2019 ..
-rw-r----- 1 leviathan1 leviathan0 133259 Aug 26  2019 bookmarks.html
```

`grep` the file for the string `leviathan1` to find the password for the next stage.

```bash
grep -hoPR "the password for leviathan1 is \K[[:alnum:]]+"
```

[*Back to top*](#overthewire---leviathan)

## Level 1

When we login to `leviathan1`, we see a program named `check` in our home directory. Let's see what happens when we run it.

```bash
$ ./check
password: password
Wrong password, Good Bye ...
```

Ok, so it appears we need to recover the password somehow. Let's debug this with `gdb` to try to figure out what the password is. We can use the `x` command to display the next *n* instructions of `main`.

```bash
$ gdb -q ./check
Reading symbols from ./check...(no debugging symbols found)...done.
(gdb) x/32i main
   0x804853b <main>:    lea    0x4(%esp),%ecx
   0x804853f <main+4>:  and    $0xfffffff0,%esp
   0x8048542 <main+7>:  pushl  -0x4(%ecx)
   0x8048545 <main+10>: push   %ebp
   0x8048546 <main+11>: mov    %esp,%ebp
   0x8048548 <main+13>: push   %ebx
   0x8048549 <main+14>: push   %ecx
   0x804854a <main+15>: sub    $0x20,%esp
   0x804854d <main+18>: movl   $0x786573,-0x10(%ebp)
   0x8048554 <main+25>: movl   $0x72636573,-0x17(%ebp)
   0x804855b <main+32>: movw   $0x7465,-0x13(%ebp)
   0x8048561 <main+38>: movb   $0x0,-0x11(%ebp)
   0x8048565 <main+42>: movl   $0x646f67,-0x1b(%ebp)
   0x804856c <main+49>: movl   $0x65766f6c,-0x20(%ebp)
   0x8048573 <main+56>: movb   $0x0,-0x1c(%ebp)
   0x8048577 <main+60>: sub    $0xc,%esp
   0x804857a <main+63>: push   $0x8048690
   0x804857f <main+68>: call   0x80483c0 <printf@plt>
   0x8048584 <main+73>: add    $0x10,%esp
   0x8048587 <main+76>: call   0x80483d0 <getchar@plt>
   0x804858c <main+81>: mov    %al,-0xc(%ebp)
   0x804858f <main+84>: call   0x80483d0 <getchar@plt>
   0x8048594 <main+89>: mov    %al,-0xb(%ebp)
   0x8048597 <main+92>: call   0x80483d0 <getchar@plt>
   0x804859c <main+97>: mov    %al,-0xa(%ebp)
   0x804859f <main+100>:        movb   $0x0,-0x9(%ebp)
   0x80485a3 <main+104>:        sub    $0x8,%esp
   0x80485a6 <main+107>:        lea    -0x10(%ebp),%eax
   0x80485a9 <main+110>:        push   %eax
   0x80485aa <main+111>:        lea    -0xc(%ebp),%eax
   0x80485ad <main+114>:        push   %eax
   0x80485ae <main+115>:        call   0x80483b0 <strcmp@plt>
```

If we look at the assembly code, we can see our password being inputted with the `getchar` functions at `<main+76>`, `<main+84>`, and `<main+92>`. It looks like this program only takes 3 characters from our input and stores it at `-0xc(%ebp)`, `-0xb(%ebp)`, and `-0xa(%ebp)`.

Now, if we look at `<main+115>`, we see a `strcmp` being called. We can also see the parameters being passed to `strcmp`, which are `-0x10(%ebp)` and `-0xc(%ebp)`. We know `-0xc(%ebp)` is our input, which means we need to find out what `-0x10(%ebp)` is.

We can figure this out by looking at `<main+18>`, which shows `0x786573` being loaded into `-0x10(%ebp)`. `0x786573` in ascii is `xes`, or `sex` in little-endian. Let's try that as our password.

```bash
$ ./check
password: sex
$ whoami
leviathan2
$ cat /etc/leviathan_pass/leviathan2
```

[*Back to top*](#overthewire---leviathan)

## Level 2

For this challenge, we are given a binary with the suid bit set. This is indicated by the `s` on the execute bit in the file permissions.

```bash
$ ls -la printfile
-r-sr-x---  1 leviathan3 leviathan2 7436 Aug 26  2019 printfile
```

Let's take a look at what this binary does.

```bash
$ gdb -q printfile
Reading symbols from printfile...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804852b <+0>:     lea    ecx,[esp+0x4]
   0x0804852f <+4>:     and    esp,0xfffffff0
   0x08048532 <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048535 <+10>:    push   ebp
   0x08048536 <+11>:    mov    ebp,esp
   0x08048538 <+13>:    push   ebx
   0x08048539 <+14>:    push   ecx
   0x0804853a <+15>:    sub    esp,0x200
   0x08048540 <+21>:    mov    ebx,ecx
   0x08048542 <+23>:    cmp    DWORD PTR [ebx],0x1
   0x08048545 <+26>:    jg     0x8048577 <main+76>
   0x08048547 <+28>:    sub    esp,0xc
   0x0804854a <+31>:    push   0x8048690
   0x0804854f <+36>:    call   0x80483c0 <puts@plt>
   0x08048554 <+41>:    add    esp,0x10
   0x08048557 <+44>:    mov    eax,DWORD PTR [ebx+0x4]
   0x0804855a <+47>:    mov    eax,DWORD PTR [eax]
   0x0804855c <+49>:    sub    esp,0x8
   0x0804855f <+52>:    push   eax
   0x08048560 <+53>:    push   0x80486a5
   0x08048565 <+58>:    call   0x80483a0 <printf@plt>
   0x0804856a <+63>:    add    esp,0x10
   0x0804856d <+66>:    mov    eax,0xffffffff
   0x08048572 <+71>:    jmp    0x80485fa <main+207>
   0x08048577 <+76>:    mov    eax,DWORD PTR [ebx+0x4]
   0x0804857a <+79>:    add    eax,0x4
   0x0804857d <+82>:    mov    eax,DWORD PTR [eax]
   0x0804857f <+84>:    sub    esp,0x8
   0x08048582 <+87>:    push   0x4
   0x08048584 <+89>:    push   eax
   0x08048585 <+90>:    call   0x8048410 <access@plt>
   0x0804858a <+95>:    add    esp,0x10
   0x0804858d <+98>:    test   eax,eax
   0x0804858f <+100>:   je     0x80485a8 <main+125>
   0x08048591 <+102>:   sub    esp,0xc
   0x08048594 <+105>:   push   0x80486b9
   0x08048599 <+110>:   call   0x80483c0 <puts@plt>
   0x0804859e <+115>:   add    esp,0x10
   0x080485a1 <+118>:   mov    eax,0x1
   0x080485a6 <+123>:   jmp    0x80485fa <main+207>
   0x080485a8 <+125>:   mov    eax,DWORD PTR [ebx+0x4]
   0x080485ab <+128>:   add    eax,0x4
   0x080485ae <+131>:   mov    eax,DWORD PTR [eax]
   0x080485b0 <+133>:   push   eax
   0x080485b1 <+134>:   push   0x80486d4
   0x080485b6 <+139>:   push   0x1ff
   0x080485bb <+144>:   lea    eax,[ebp-0x208]
   0x080485c1 <+150>:   push   eax
   0x080485c2 <+151>:   call   0x8048400 <snprintf@plt>
   0x080485c7 <+156>:   add    esp,0x10
   0x080485ca <+159>:   call   0x80483b0 <geteuid@plt>
   0x080485cf <+164>:   mov    ebx,eax
   0x080485d1 <+166>:   call   0x80483b0 <geteuid@plt>
   0x080485d6 <+171>:   sub    esp,0x8
   0x080485d9 <+174>:   push   ebx
   0x080485da <+175>:   push   eax
   0x080485db <+176>:   call   0x80483e0 <setreuid@plt>
   0x080485e0 <+181>:   add    esp,0x10
   0x080485e3 <+184>:   sub    esp,0xc
   0x080485e6 <+187>:   lea    eax,[ebp-0x208]
   0x080485ec <+193>:   push   eax
   0x080485ed <+194>:   call   0x80483d0 <system@plt>
   0x080485f2 <+199>:   add    esp,0x10
   0x080485f5 <+202>:   mov    eax,0x0
   0x080485fa <+207>:   lea    esp,[ebp-0x8]
   0x080485fd <+210>:   pop    ecx
   0x080485fe <+211>:   pop    ebx
   0x080485ff <+212>:   pop    ebp
   0x08048600 <+213>:   lea    esp,[ecx-0x4]
   0x08048603 <+216>:   ret
```

Since this program is pretty simple, we can get a pretty good picture of what's going on based on the disassembled code. Here's a rough breakdown of main's source code:

```c++
if !(argc > 1) {
   puts("*** File Printer ***");
   printf("Usage: %s filename\n", argv[0]);
   return -1;
}
else {
   if (access(argv[1], 4) == 0) {
      snprintf(command, 0x1ff, "/bin/cat %s", argv[1]);
      setreuid(geteuid(), geteuid());
      system(command);
      return 0;
   }
   else {
      puts("You cant have that file...");
      return 1;
   }
}
```

The important thing to note is if we pass the `access` check, our file will then be read by passing `/bin/cat filename` to system. If we look at the documentation for [access](https://linux.die.net/man/2/access), we see that the value `4` means it's checking if we have the read permission on a file. Also, since the suid bit is set, the command passed to `system` will be executed with `leviathan3`'s permissions.

The great thing about `cat` is that we can read multiple files at once by separating the filenames with a space. Conveniently enough, we are also allowed to have spaces in filenames. We can take advantage of these two things to create a filename, which we have read access to, with a space in it. However, when it is passed to `system`, it will try to read the filename as two separate files, which will allow us to read the password file as `leviathan3`.

```bash
file="/tmp/ leviathan3"; touch "$file"; cd /etc/leviathan_pass/; ~/printfile "$file"; rm "$file"
```

[*Back to top*](#overthewire---leviathan)

## Level 3

For this challenge, we have another suid binary, `level3`.

```bash
$ ls -la level3
-r-sr-x--- 1 leviathan4 leviathan3 10288 Aug 26  2019 level3
```

This time, when we disassemble main, we see an unusual function, `do_stuff`, being called. Let's see what's happening in `do_stuff`.

```bash
$ gdb -q level3
Reading symbols from level3...done.
(gdb) disassemble do_stuff
Dump of assembler code for function do_stuff:
   0x0804855b <+0>:     push   %ebp
   0x0804855c <+1>:     mov    %esp,%ebp
   0x0804855e <+3>:     push   %ebx
   0x0804855f <+4>:     sub    $0x114,%esp
   0x08048565 <+10>:    movl   $0x706c6e73,-0x113(%ebp)
   0x0804856f <+20>:    movl   $0x746e6972,-0x10f(%ebp)
   0x08048579 <+30>:    movw   $0xa66,-0x10b(%ebp)
   0x08048582 <+39>:    movb   $0x0,-0x109(%ebp)
   0x08048589 <+46>:    mov    0x804a040,%eax
   0x0804858e <+51>:    sub    $0x4,%esp
   0x08048591 <+54>:    push   %eax
   0x08048592 <+55>:    push   $0x100
   0x08048597 <+60>:    lea    -0x108(%ebp),%eax
   0x0804859d <+66>:    push   %eax
   0x0804859e <+67>:    call   0x80483f0 <fgets@plt>
   0x080485a3 <+72>:    add    $0x10,%esp
   0x080485a6 <+75>:    sub    $0x8,%esp
   0x080485a9 <+78>:    lea    -0x113(%ebp),%eax
   0x080485af <+84>:    push   %eax
   0x080485b0 <+85>:    lea    -0x108(%ebp),%eax
   0x080485b6 <+91>:    push   %eax
   0x080485b7 <+92>:    call   0x80483d0 <strcmp@plt>
   0x080485bc <+97>:    add    $0x10,%esp
   0x080485bf <+100>:   test   %eax,%eax
   0x080485c1 <+102>:   jne    0x80485fe <do_stuff+163>
   0x080485c3 <+104>:   sub    $0xc,%esp
   0x080485c6 <+107>:   push   $0x8048750
   0x080485cb <+112>:   call   0x8048410 <puts@plt>
   0x080485d0 <+117>:   add    $0x10,%esp
   0x080485d3 <+120>:   call   0x8048400 <geteuid@plt>
   0x080485d8 <+125>:   mov    %eax,%ebx
   0x080485da <+127>:   call   0x8048400 <geteuid@plt>
   0x080485df <+132>:   sub    $0x8,%esp
   0x080485e2 <+135>:   push   %ebx
   0x080485e3 <+136>:   push   %eax
   0x080485e4 <+137>:   call   0x8048430 <setreuid@plt>
   0x080485e9 <+142>:   add    $0x10,%esp
   0x080485ec <+145>:   sub    $0xc,%esp
   0x080485ef <+148>:   push   $0x8048764
   0x080485f4 <+153>:   call   0x8048420 <system@plt>
   0x080485f9 <+158>:   add    $0x10,%esp
   0x080485fc <+161>:   jmp    0x804860e <do_stuff+179>
   0x080485fe <+163>:   sub    $0xc,%esp
   0x08048601 <+166>:   push   $0x804876c
   0x08048606 <+171>:   call   0x8048410 <puts@plt>
   0x0804860b <+176>:   add    $0x10,%esp
   0x0804860e <+179>:   mov    $0x0,%eax
   0x08048613 <+184>:   mov    -0x4(%ebp),%ebx
   0x08048616 <+187>:   leave
   0x08048617 <+188>:   ret
```

Much like the last level, we need to pass a check before the binary will call `setreuid`. If we look at `<do_stuff+92>`, we see there is a `strcmp` being called, which is comparing our input with a string at `esp-0x113`. We can use `gdb` to pause right before the check and print the value of the string.

```
(gdb) break *0x0804859e
Breakpoint 1 at 0x804859e: file level3.c, line 10.
(gdb) r
Starting program: /home/leviathan3/level3

Breakpoint 1, 0x0804859e in do_stuff () at level3.c:10
10      level3.c: No such file or directory.
(gdb) x/s $ebp-0x113
0xffffd555:     "snlprintf\n"
```

Look's like all we have to do is send `snlprintf` to the program to pass the check.

```bash
$ ./level3
Enter the password> snlprintf
[You've got shell]!
$ cat /etc/leviathan_pass/leviathan4
```

[*Back to top*](#overthewire---leviathan)

## Level 4

For this challenge, we have a file named `bin` in a hidden directory, `.trash`. When you run it, it prints the password as a binary string. All we have to do is convert the binary string back to ascii.

```bash
for i in $(~/.trash/bin | sed 's/ /\n/g'); do echo -ne "\x$(printf "%x" $(( 2#$i )))"; done
```

[*Back to top*](#overthewire---leviathan)

## Level 5

When we disassemble `main`, we see an argument being passed to `fopen`.

```bash
$ gdb -q leviathan5
Reading symbols from leviathan5...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x080485db <+0>:     lea    0x4(%esp),%ecx
   0x080485df <+4>:     and    $0xfffffff0,%esp
   0x080485e2 <+7>:     pushl  -0x4(%ecx)
   0x080485e5 <+10>:    push   %ebp
   0x080485e6 <+11>:    mov    %esp,%ebp
   0x080485e8 <+13>:    push   %ecx
   0x080485e9 <+14>:    sub    $0x14,%esp
   0x080485ec <+17>:    sub    $0x8,%esp
   0x080485ef <+20>:    push   $0x8048720
   0x080485f4 <+25>:    push   $0x8048722
   0x080485f9 <+30>:    call   0x8048490 <fopen@plt>
...
(gdb) x/s 0x8048722
0x8048722:      "/tmp/file.log"
```

It looks like this program is trying to read a file named `/tmp/file.log`. Let's create a symbolic link to the password so the program will read the password when it tries to read the `file.log`.

```bash
ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log;~/leviathan5
```

[*Back to top*](#overthewire---leviathan)

## Level 6

For this challenge, we have suid binary that is looking for a 4 digit code. We can retrieve the code using gdb:

```
(gdb) break *0x0804858f
Breakpoint 1 at 0x804858f
(gdb) run 0000
Starting program: /home/leviathan6/leviathan6 0000

Breakpoint 1, 0x0804858f in main ()
(gdb) x/u $ebp-0xc
0xffffd69c:     7123
```

Now, we can use the pin to get a shell.

```bash
$ ./leviathan6 7123
$ whoami
leviathan7
$ cat /etc/leviathan_pass/leviathan7
```

[*Back to top*](#overthewire---leviathan)

## Level 7

Looks like we made it to the last level.

```bash
$ ls
CONGRATULATIONS
$ cat CONGRATULATIONS
Well Done, you seem to have used a *nix system before, now try something more serious.
```

[*Back to top*](#overthewire---leviathan)

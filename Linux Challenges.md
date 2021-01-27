Linux Challenges

# Linux Challenges

# Task 1 Linux Challenges introduction
Deploy Virtual Machine and log in as Garry using the given credentials.
1. How Many Virtual Filles Can you see in Garry's Directory?

- type command ls to see visible files. there are 3.
![files in garry home.png](./f18f337f6dca441eb30a67493f8c6f50.png)

# Task 2 The Basics

2. What is flag1?
- run `cat` command on flag1.txt which you saw in garry's home directory.
![flag1.png](./6e8f8ac3e91a4a96b495b5ea4146e596.png)

3. What is flag2?
- as instructed in flag1.txt, log into bob's account. we use `su` command.
- list files in bob's home directory using ls, we can see flag2. run `cat` on flag2.txt
![flag2.png](./f4763b61f4114003a535e6c4ad327bc6.png)

4. Flag 3 is located where bob's bash history gets stored.
- bob's history is stored in the .bash_history file. It's a hidden file in a user's home directory. check if you can find using ls -a.
- read the file and you'll see at the top of it a long string which is flag3.
![flag3.png](./ccc49431aae242cb94aa24747c636adb.png)

5. Flag 4 is located where cron jobs are created.
- cron jobs are created in the crontab. to see the jobs listed in crontab, we run 'crontab -l'
![flag4.png](./bff60bd171ae439d8fc308edd822e9cf.png)

6. Find and retrieve flag5.
- use locate to find a file that is named flag5.
- found file, read it.
![flag5.png](./c36d71f9096949a78101b05871fbac25.png)

7. "Grep" through flag 6 and find the flag. The first 2 characters of the flag is c9.
- `locate` flag6.
- use `grep` to find string.
![flag6.png](./6300ec79a77b4225afbcdd81cd61716d.png)

8. Look at the systems processes. What is flag 7.
- use ps command to list processes. use -ef switch to see full format listings.


![Screen Shot 2021-01-22 at 9.03.28 AM.png](./3bb3ad0d2b5e49d69a32c97e6c714b9b.png)

9. De-compress and get flag 8.
- `locate` flag8. 
- use `tar -zxvf` to unzip and "un-tar" a tar.gz file.
![flag7.png](./ceaebc47f84845379379a3878bf55d2a.png)

10. By looking in your hosts file, locate and retrieve flag 9.
- hosts file in /etc directory. it is a file that translates hostnames to ip addresses.
- read the hosts file and you'll see a hostname that's a long string that's actually flag 9.
![flag9.png](./194ebfbda3194f1d8ed46e3a8501505b.png)
 
11. Find all other users on the system. What is flag 10?
- users can be found in the etc/passwd file.
- you'll notice a user whose name is a long string.
![flag10.png](./348177ae16334a6780f38ec6a59a2b45.png)

# Task 3 Linux Functionality

12. Run the command flag11. Locate where your command aliases are stored and get flag 11.
- command aliases are stored in .bashrc in the home directory
- grep the .bashrc file for flag11
![flag11.png](./d8d91cc140334fc9ac2c4948d819ce6d.png)


13. Flag12 is located were MOTD's are usually found on an Ubuntu OS. What is flag12?
- find motd's location using `locate`
- we then grep this directory we found recursively for the word 'flag'
![flag12-1.png](./05d6717afdfc4c94a6f8ba18c41ee85f.png)
![flag12-2.png](./fae5d7ea54c14f00b0a7b36879944dff.png)

14. Flag12 is located were MOTD's are usually found on an Ubuntu OS. What is flag12?
- In bob's home directory you'll find the flag13 directory
- compare the files inside using `diff`
![flag13.png](./2f1738cedde54ebea254d140f2524ea5.png)

15. Where on the file system are logs typically stored? Find flag 14.
- they're typically stored in /var/logs.
- let's list the files in the folder
![flag14-1.png](./b9ebd13ce91a43c3bc5e2603e5e48d5e.png)
- from the list, there's a file called flagtourteen.txt
- from the previous flags we know that the flag is a long string.
- tried using the following one-line command to list the longest strings in the file instead of manually searching for it all over the file.
```
sed 's/ /\n/g' YOUR_FILENAME | sort | uniq | awk '{print length, $0}' | sort -nr | head -n 1
```
- at the top of the list you'll see the flag.
![flag14-2.png](./784a2c9f73c544bc8ab86614f9acac8c.png)


16. Can you find information about the system, such as the kernel version etc.
Find flag 15.
- information can be found in /etc/*release
![Screen Shot 2021-01-24 at 10.56.02 PM.png](./6ae32b6fde9d402baa09f28d3434d9ee.png)

17. Flag 16 lies within another system mount.
- /media is another system mount.
- we explore the directory by doing `ls` recursively.
- within the layers, we can find the flag.
![flag16.png](./824dc7653c494d119ee7358268f42275.png)

18. Login to alice's account and get flag 17. Her password is TryHackMe123
![flag17.png](./11edc60ba801494aa416c71d11a9ded8.png)

19. Find the hidden flag 18.
- locate then read
![flag18.png](./b957e3e23e2d4542b8e83a3254867e3c.png)

20. Read the 2345th line of the file that contains flag 19.
- use `sed`
-  `-n'Np'` flag gets the Nth line of a file 
![flag19.png](./eea45a49dfa94f5eb9f86d8dbc97617f.png)


# Task 4 Data Representation, Strings and Permissions

21. Find and retrieve flag 20.
- flag20 is also in alice's home directory
- it's in base 64, to decode we run 
```base 64 -d flag20 ```
![flag20.png](./d1b0916ce36246a3a7ef3387503c6224.png)

22. Inspect the flag21.php file. Find the flag.
- reading with `cat`, by default it does not read non-printable characters. There's a ^M character in the file. If you run `man cat`, you'll see that it's a non-printable character and preventing you from reading the rest of the text that contains the flag.
- if you use `strings` or `less` command, the flag will display. you can also use `cat -v`
![flag21.png](./a202d1b3b1104527ac281df96c8b0b6c.png)

23. Locate and read flag 22. Its represented as hex.
- `xxd` command creates a hex dump or reverse of it
- there are other commands that do hexdumps but xxd is the only one that reverses.
- `-r` flag is the reverse process. and converts hex to binary.
-  `p` flag indicates format of hex is in continuous postcript.
![flag22.png](./e7ab7e56cdcc40e1abdbe03e4c8b4c8f.png)

24. Locate, read and reverse flag 23.
- flag is in Alice's home directory
- we use the `rev` command when reversing a string
- I almost forgot about this command because reversing could mean a lot of things... but there's only 1 simple long string here, there's not much you can do.
![flag23.png](./c09f5b1cc6b64cf2a1d3f70c26618828.png)

25. Analyse the flag 24 compiled C program. Find a command that might reveal human readable strings when looking in the machine code code.
- human readable strings can be seen via the `strings` command.
![flag24.png](./2910bd50fda044329f39900a5a236721.png)

26. Flag25 does not exits.
- ok.

27. Find flag 26 by searching the all files for a string that begins with 4bceb and is 32 characters long. 

- we list all files (in their full file names) excluding those from mounts and grep them for strings that are 32 characters long. we can also search for those starting with 4bceb. it takes so long to run the two conditions together and just running one of them already yields the flag so...
![flag26.png](./dd90634fa1b64d0480ab6cc88f3bde30.png)



28. Locate and retrieve flag 27, which is owned by the root user.
- since it is owned by the root user, maybe we have sudo access to it.
- we run `sudo -l` to see where we can run sudo and we find flag27 there. we can run commands 
- we run `sudo cat` to read the file.
![flag27.png](./854112a7ff1a41d790f7107bccba9d5d.png)



29. Whats the linux kernel version?
- uname command displays basic info about the os and hardware
- `-r` flag reveals the release version being used.
![flag28.png](./95b1e32bbc6040b190a52d89232f2736.png)

30. Find the file called flag 29 and do the following operations on it:
	Remove all spaces in file.
	Remove all new line spaces.
	Split by comma and get the last element in the
	split.
	
- flag is in garry's home directory
- we use `tr -d '[:space]'` to remove spaces and new lines
- we use `sed 's/<delimiter>/\n/g'` to delimit the file, for the delimiter we use a comma `,`
![flag29-1.png](./16b2f2b3ecc24060b2ebfc508523deb0.png)
- we can then get the flag  from the last line. note: you can get the tail of the output using `tail` command but i figured it won't be big and just scrolled to the last line.
![flag29-2.png](./78060a7d1aae4faa89cd4fd18134b50f.png)


# Task 5 SQL, FTP, Groups and RDP

31. Use curl to find flag30.
- no ip/hostname was provided. figured it would be localhost
![flag30.png](./13fc4b0bbf03445588507af6d976c872.png)

32. Flag 31 is a MySQL database name.
	MySQL username: root
	MySQL password: hello
- we login using `mysql --user=root --password` command and use given credentials
- we then list for the databases using `show databases` query and see a database name with a long string.
![flag31.png](./47416274f4774224ace9472c55128356.png)

33. Bonus flag question, get data out of the table from the database you found above!
- we query for the tables and select data from it.
![flag 31-bonus.png](./9b20fdc6fc8c43bc81895608b5edd73d.png)

34. Using SCP, FileZilla or another FTP client download flag32.mp3 to reveal flag 32.
- used scp with the following syntax
``` scp username@hostip:\path\to\source\file \target\destination\directory```
- listen to flag32 for the flag. yes you have to listen to the mp3 file.

![flag32.png](./018e6d80272b4fafbf1bc1427a7a9abb.png)


35. Flag 33 is located where your personal $PATH's are stored.
- $Path is stored in the `.profile` file. 
- Alice's .profile doesn't have the flag. We search for it in other users..we try Bob.
- Bob has the flag.
![flag33.png](./1ed7b353728a427db75c7b3956f35ecf.png)

36. Switch your account back to bob. Using system variables, what is flag34?
- we get the system variable $flag34 stored in Bob's account to get the flag
![flag34.png](./4c0abac5feba45f98640c334c0ac87c6.png)

37. Look at all groups created on the system. What is flag 35?
- we `grep` for the flag in the `etc/groups` file which lists the groups 
![flag35.png](./25df351ea846468483b041e116cedaa3.png)

38. Find the user which is apart of the "hacker" group and read flag 36.
- we `grep` for the group 'hacker' in the `/etc/group` file. we find that bob is a member
- we login as bob and we access the file.
![flag36.png](./1c491d21680e4df18910c7347a7e716e.png)

39. Well done! You've completed the LinuxCTF room!
- yay



























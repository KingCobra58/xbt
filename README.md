# XBT Tracker

### Installing under Linux

The following commands can be used to install the dependencies on Debian and Ubuntu. The g++ version should be at least 7.

```
apt install cmake default-libmysqlclient-dev g++ git libboost-dev libsystemd-dev make zlib1g-dev
```

The following commands can be used to install some of the dependencies on CentOS, Fedora and Red Hat. The g++ version should be at least 7.

```
yum install boost-devel cmake gcc-c++ git mysql-devel 
```

Enter the following commands in a terminal. Be patient while g++ is running, it'll take a few minutes.

```
git clone https://github.com/KingCobra58/xbt
cd xbt/Tracker
./make.sh
```
Now edit xbt_tracker.conf:
```
vi xbt_tracker.conf
```
Check at the bottom left of the console and if it says -- REPLACE -- press the INSERT/INS key on your keyboard and the text should change to -- INSERT --. You can now use vi as you would any other text editor.

You should now proceed to add the same database credentials as you used in the xbtitFM installation. (Check include/settings.php from the tracker files if you need a reminder).
```
mysql_user = 
mysql_password = 
mysql_database = 
```
Once done, Press the Escape/ESC key on your keyboard and then type:
```
:x
```
And press the RETURN/ENTER key on your keyboard. This will save the file including your changes.

Once this is done you can start xbt by entering the following command
```
./xbt_tracker
```

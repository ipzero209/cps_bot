## cps_bot
Uses SNMP to pull the active CPS numbers (per protocol) for each zone on the firewall


This script will poll OID .1.3.6.1.4.1.25461.2.1.2.3.10 and parse the output for each zone configured on the target firewall. This script only supports SNMP 2c.

# Preparation

The system you run this script on will need to have Palo Alto Networks v8.0 MIBS or later installed.

> Sample instructions for Ubuntu/Debian
  1. Download 8.0 (or later) PAN-OS MIBs from https://www.paloaltonetworks.com/documentation/misc/snmp-mibs
  2. Copy the MIBs as '.xtx' files to the proper location. On Ubuntu/Debian systems this location is /usr/share/mibs
  3. Modify your snmp.conf file to include the PAN MIBs.
    A. snmp.conf file is located at /etc/snmp. If it doesn't exist, you can create it.
    B. Add 'mibs +ALL' to snmp.conf
  4. To get all standard MIBS: 
    A. Run 'sudo apt-get install snmp-mibs-downloader'
    B. Run 'sudo download-mibs'
    
# Test

To ensure that all of the MIBs are correctly loaded, run the following command:

```
snmptable -v 2c -Pe -c <read_string> <fw_ip> .1.3.6.1.4.1.25461.2.1.2.3.10 2>/dev/null
```

The result will look similar to this:

```
SNMP table: PAN-COMMON-MIB::panZoneTable

 panZoneName                             panZoneActiveTcpCps                             panZoneActiveUdpCps                         panZoneActiveOtherIpCps
    L3_Trust Wrong Type (should be Gauge32 or Unsigned32): 0 Wrong Type (should be Gauge32 or Unsigned32): 0 Wrong Type (should be Gauge32 or Unsigned32): 0
  L3_Untrust Wrong Type (should be Gauge32 or Unsigned32): 0 Wrong Type (should be Gauge32 or Unsigned32): 0 Wrong Type (should be Gauge32 or Unsigned32): 0
  
 ```
 
 If your output looks like this, then you are ready to run the script. The "Wrong Type" warnings are due to a bug in PAN-OS that will be resolved in an upcoming maintenance release. Once the issue is resolved, this repo will be updated. This script works with the type error.
 
 
 # RUN
 
./cps_bot.py


1. You will be prompted for the IP of the firewall.
2. You will be prompted for the SNMP read string.
3. You will be prompted for the number of minutes that you would like to poll
4. Script runs, collects data, and provides a summary.

# Output

The script will create one subdirectory for each zone on the firewall:

```
-rwxr-xr-x  1 cstancill cstancill 4933 Jul 18 10:56 cps_bot.py*
drwxrwxr-x  2 cstancill cstancill 4096 Jul 19 15:45 L3_Trust/
drwxrwxr-x  2 cstancill cstancill 4096 Jul 19 15:45 L3_Untrust/
-rw-rw-r--  1 cstancill cstancill  634 Jul 19 15:46 summary.txt
```
The subdirectory for each zone will contain the CPS data collected for each protocol:

```
-rw-rw-r-- 1 cstancill cstancill   12 Jul 19 15:46 L3_Trust_other_sample.log
-rw-rw-r-- 1 cstancill cstancill   12 Jul 19 15:46 L3_Trust_tcp_sample.log
-rw-rw-r-- 1 cstancill cstancill   12 Jul 19 15:46 L3_Trust_udp_sample.log
```

In the directory where the script was run, there will be a summary file created which contains suggested alert/activate/max thresholds per zone per protocol. Summary example:

```
L3_Trust

        tcp
                Alert Threshold:        0
                Activate Threshhold:    0.0
                Max Threshold:          0.0


        udp
                Alert Threshold:        0
                Activate Threshhold:    0.0
                Max Threshold:          0.0


        other
                Alert Threshold:        0
                Activate Threshhold:    0.0
                Max Threshold:          0.0

==================================================================

L3_Untrust

        tcp
                Alert Threshold:        0
                Activate Threshhold:    0.0
                Max Threshold:          0.0


        udp
                Alert Threshold:        0
                Activate Threshhold:    0.0
                Max Threshold:          0.0


        other
                Alert Threshold:        0
                Activate Threshhold:    0.0
                Max Threshold:          0.0

==================================================================
```

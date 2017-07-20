#!/usr/bin/python

import os
import re
from time import sleep
import math
import pudb



def getTable(ip, string):
    """Fetches CPS table from the specified device and returns a multi-line string."""
    response = os.popen('snmptable -v 2c -Pe -c {} {} .1.3.6.1.4.1.25461.2.1.2.3.10 2>/dev/null'.format(string, ip)).read()
    response = response.split('\n')
    return response


def getZones(in_string):
    """Parses response for zones on the firewall. Returns a list of the zones."""
    z_list = []
    for line in in_string:
        if "Type" in line:
            line = line.strip(' ')
            line = line[:line.find('Wrong')]
            line = line.strip(' ')
            z_list.append(line)
    return z_list

def loadData(zone):
    """Loads sample data for a given zone and returns it in a dictionary."""
    sample_dict = {'tcp':[], 'udp':[], 'other':[]}
    prot_list = ['tcp', 'udp', 'other']
    for protocol in prot_list:
        infile = open('./{}/{}_{}_sample.log'.format(zone, zone, protocol), 'r+')
        for line in infile:
            line = line.strip('\n')
            sample_dict[protocol].append(line)
    return sample_dict

def findPeak(samples):
    """Finds highest sample in the list of samples passed in."""
    high = 0
    for sample in samples:
        if int(sample) > high:
            high = int(sample)
    return high


def findMean(samples):
    """Finds and returns the mean of the samples passed in."""
    sum = 0
    for sample in samples:
        sum += int(sample)
    avg = sum/len(samples)
    return avg

def findSD(samples):
    """Finds and returns the mean and standard deviation for the set of samples passed in."""
    mean = findMean(samples)
    diff_list = []
    for sample in samples:
        diff = int(sample) - int(mean)
        diff = diff ** 2
        diff_list.append(diff)
    diff_avg = findMean(diff_list)
    sd = math.sqrt(diff_avg)
    return sd





def main():
    fw_ip = raw_input("What firewall would you like to poll? ")
    read_string = raw_input("What is the snmp read string for the firewall \(SNMP version support only at this time\)? ")
    minutes = raw_input("How many minutes would you like to poll? ")
    poll_num = int(minutes) * 6

    # Regex for matching
    match_unsigned = re.compile('Unsigned32')
    match_gauge = re.compile('Gauge32')
    match_count = re.compile('([0-9]+)')


    # Get list of zones
    zone_data = getTable(fw_ip, read_string)
    zone_list = getZones(zone_data)


    # Create subdirectories for zone samples
    for zone in zone_list:
        os.system('mkdir ./{}'.format(zone))


    # Initialize poll counter
    poll_count = 0

    # pudb.set_trace()
    # Gather data points
    while poll_count < poll_num:
        this_resp = getTable(fw_ip, read_string)
        for line in this_resp:
            if "Type" in line:
                zone = line.strip(' ')
                zone = zone[:zone.find('Wrong')]
                zone = zone.strip(' ')
                line = line[line.find('Wrong'):]
                line = re.sub(match_unsigned, 'p', line)
                line = re.sub(match_gauge, 'p', line)
                cps = match_count.findall(line)
                if cps is not None:
                    tcp_outfile = open('./{}/{}_tcp_sample.log'.format(zone, zone), 'a', 0)
                    udp_outfile = open('./{}/{}_udp_sample.log'.format(zone, zone), 'a', 0)
                    other_outfile = open('./{}/{}_other_sample.log'.format(zone, zone), 'a', 0)
                    tcp_outfile.write(str(cps[0]) + '\n')
                    udp_outfile.write(str(cps[1]) + '\n')
                    other_outfile.write(str(cps[2]) + '\n')
                    tcp_outfile.close()
                    udp_outfile.close()
                    other_outfile.close()
        poll_count += 1
        sleep(10)

    summary_outfile = open('./summary.txt', 'w+')

    # Calculate suggested thresholds
    prot_list = ['tcp', 'udp', 'other']
    for zone in zone_list:
        zone_data_dict = loadData(zone)
	summary_outfile.write('{}\n'.format(zone))
        for protocol in prot_list:
            peak = findPeak(zone_data_dict[protocol])
            mean = findMean(zone_data_dict[protocol])
            sd = findSD(zone_data_dict[protocol])
            alert = int(mean) + int(sd)
            activate = 1.1 * int(peak)
            maximum = 1.1 * 1.1 * int(peak)
            summary_outfile.write('\n'
                                  '\t{}\n'
                                  '\t\tAlert Threshold: \t{}\n'
                                  '\t\tActivate Threshhold: \t{}\n'
                                  '\t\tMax Threshold:\t\t{}\n\n'.format(protocol, alert, activate, maximum))
        summary_outfile.write("==================================================================\n\n")
    summary_outfile.close()
    print "Analysis Complete!!"



if __name__ == "__main__":
    main()



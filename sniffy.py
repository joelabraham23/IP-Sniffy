from scapy.all import *
import ipaddress
import time
import boto3
from botocore.exceptions import ClientError
import os
import logging

# Sourced from 
# https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3-uploading-files.html
def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True 


def sniffy(): 
    # Set to store unique IP addresses
    ip_details = {}


    def is_private_ip(ip):
        """Check if an IP address is private."""
        private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16')
        ]
        return any(ipaddress.ip_address(ip) in private_range for private_range in private_ranges)

    def packet_callback(packet):
            if IP in packet:
                current_time = time.strftime("%Y-%m-%d %H:%M:%S")
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if not is_private_ip(src_ip):
                    # Update src_ip count and set the most recent timestamp
                    ip_details[src_ip] = (ip_details.get(src_ip, (0, ''))[0] + 1, current_time)
                if not is_private_ip(dst_ip):
                    # Update dst_ip count and set the most recent timestamp
                    ip_details[dst_ip] = (ip_details.get(dst_ip, (0, ''))[0] + 1, current_time)


    def save_ips_to_file():
        with open("ip_log.txt", "w") as file:
            for ip, (count, timestamp) in ip_details.items():
                # Write the most recent timestamp of the individual IP connection
                file.write(f"{timestamp} - {ip} - {count}\n")
            # Clear the dictionary after saving to the file
            ip_details.clear()

    print("Logging IP addresses...")
    # Continuously sniff packets and save IPs every hour
    while True:
        sniff(prn=packet_callback, filter="ip", iface="en0", store=0, timeout=60)
        save_ips_to_file()
        if not upload_file("ip_log.txt", "comp6441-sap", "device_01.txt"):
            print("Upload failed")
    # This script will run indefinitely. Every minute, it will save the new IP addresses 
    # to the "ip_log.txt" file and then continue sniffing. Private IP addresses are 
    # excluded from being saved to the file.

sniffy()



#!/usr/bin/python3
# -*- coding: utf8 -*-

"""
This program checks the reputation of a list of IP V4 addresses provided in stdin.
Initial release is based on information from Shodan, VirusTotal, ApiVoid and IpQualityScore.
Free accounts of these services can be used, but it limits the amount of requests (per minute/day/month). 
API keys must be stored in the .env file : SHODAN_API_KEY VIRUS_TOTAL_KEY APIVOID_KEY IPQS_KEY 
V1.0
23 october 2022
MIT licence
https://tutoduino.fr/
"""

from distutils.log import info
import ipaddress
import shodan
import requests
import json
import os
import sys
from dotenv import load_dotenv
from dataclasses import dataclass


@dataclass
class ApiVoidInfo:
    """
    """
    risk_score: int
    detection_rate: str

    def __init__(self, risk_score, detection_rate) -> None:
        self.risk_score = risk_score
        self.detection_rate = detection_rate




@dataclass
class ShodanInfo:
    """
    """
    nb_open_ports: int

    def __init__(self, nb_open_ports) -> None:
        self.nb_open_ports = nb_open_ports


@dataclass
class VirusTotalInfo:
    """
    """
    nb_malicious: int
    nb_suspicious: int
    reputation: int
    harmless_votes: int
    malicious_votes: int

    def __init__(self, nb_malicious, nb_suspicious, reputation, harmless_votes, malicious_votes) -> None:
        self.nb_malicious = nb_malicious
        self.nb_suspicious = nb_suspicious
        self.reputation = reputation
        self.harmless_votes = harmless_votes
        self.malicious_votes = malicious_votes


@dataclass
class IpQualityScoreInfo:
    """
    """
    fraud_score: int
    bot_activity: int
    vpn_status: bool
    proxy_status: bool
    tor_status: bool

    def __init__(self, fraud_score, bot_activity, vpn_status, proxy_status, tor_status) -> None:
        self.fraud_score = fraud_score
        self.bot_activity = bot_activity
        self.vpn_status = vpn_status
        self.proxy_status = proxy_status
        self.tor_status = tor_status


@dataclass
class DisplayIpReputationElements:
    """
    Class to store elements of IP reputation.
    """
    ip_addr: str
    private: bool
    shodan_info: ShodanInfo
    vt_info: VirusTotalInfo
    ipqs_info: IpQualityScoreInfo
    apivoid_info: ApiVoidInfo

    def __init__(self, ip_addr: str, private: bool, shodan_info: ShodanInfo, vt_info: VirusTotalInfo, ipqs_info: IpQualityScoreInfo, apivoid_info: ApiVoidInfo) -> None:
        self.ip_addr = ip_addr
        self.private = private
        self.shodan_info = shodan_info
        self.vt_info = vt_info
        self.ipqs_info = ipqs_info
        self.apivoid_info = apivoid_info

    def display_IpReputationElements(self):
        if self.private:
            print("{} is a private IP address".format(self.ip_addr))
        else:
            print("{} is a public IP address".format(self.ip_addr))
            if self.shodan_info is not None:
                print(
                    "Shodan           -> number of open ports: {}".format(self.shodan_info.nb_open_ports))
            if self.apivoid_info is not None:
                print(
                    "ApiVoid          -> Risk score: {}".format(self.apivoid_info.risk_score))    
                print(
                    "ApiVoid          -> Detection rate: {}".format(self.apivoid_info.detection_rate))                    
            if self.vt_info is not None:
                print(
                    "VirusTotal       -> Number of reports saying it is malicious: {}".format(self.vt_info.nb_malicious))
                print(
                    "VirusTotal       -> Number of reports saying it is suspicious: {}".format(self.vt_info.nb_suspicious))
                print(
                    "VirusTotal       -> Reputation (<0 is suspicious): {}".format(self.vt_info.reputation))
                print(
                    "VirusTotal       -> Harmless votes: {}".format(self.vt_info.harmless_votes))
                print(
                    "VirusTotal       -> Malicious votes: {}".format(self.vt_info.malicious_votes))
            if self.ipqs_info is not None:
                print(
                    "IpQualityScore   -> Fraud score (>75 is suspicious): {}".format(self.ipqs_info.fraud_score))
                print(
                    "IpQualityScore   -> Bot activity: {}".format(self.ipqs_info.bot_activity))
                print(
                    "IpQualityScore   -> VPN status: {}".format(self.ipqs_info.vpn_status))
                print(
                    "IpQualityScore   -> Proxy status: {}".format(self.ipqs_info.proxy_status))
                print(
                    "IpQualityScore   -> Tor status: {}".format(self.ipqs_info.tor_status))
        print("------------------------------------------")


class IpAddressCheckReputation(object):
    """
    A class used to check reputation of an IP V4 address
    Based on results from Shodan, VirusTotal and IpQualityScore
    """

    def __init__(self, ip):

        if ip is None:
            raise ValueError(
                "IpAddress constructor must be called with an IP V4 address as argument")
        self.ip = ip

        # Get API keys from .env file
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.virustotal_api_key = os.getenv("VIRUS_TOTAL_KEY")
        self.ipqualityscore_api_key = os.getenv("IPQS_KEY")
        self.apivoid_api_key = os.getenv("APIVOID_KEY")
        

        # Connect to Shodan API
        if self.shodan_api_key is not None:
            try:
                self.shodan_api = shodan.Shodan(self.shodan_api_key)
            except shodan.APIError as e:
                print('Shodan error: {}'.format(e), file=sys.stderr)

    def apivoid_stats(self) -> ApiVoidInfo:
        """
        Call ApiVoid API to get information
        """

        if self.apivoid_api_key is None:
            return None

        try:
            url = "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key="+self.apivoid_api_key+"&ip="+format(self.ip)
            response = requests.get(url)
            res = json.loads(response.text)
            if res["success"] == True:
                risk_score = res["data"]["report"]["risk_score"]["result"]
                detection_rate = res["data"]["report"]["blacklists"]["detection_rate"]
            else:
                return None
        except Exception as e:
            print("ApiVoid error: {}".format(e), file=sys.stderr)
            return None

        return ApiVoidInfo(risk_score, detection_rate)

        

    def virustotal_stats(self) -> VirusTotalInfo:
        """
        Call VirusTotal API to get information
        """
        if self.virustotal_api_key is None:
            return None
        try:
            url = "https://www.virustotal.com/api/v3/ip_addresses/" + \
                format(self.ip)
            headers = {
                "accept": "application/json",
                "x-apikey": self.virustotal_api_key
            }
            response = requests.get(url, headers=headers)
            res = json.loads(response.text)
            nb_malicious = res["data"]["attributes"]["last_analysis_stats"]["malicious"]
            nb_suspicious = res["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            reputation = res["data"]["attributes"]["reputation"]
            harmless_votes = res["data"]["attributes"]["total_votes"]["harmless"]
            malicious_votes = res["data"]["attributes"]["total_votes"]["malicious"]

        except Exception as e:
            print("VirusTotal error: {}".format(e), file=sys.stderr)
            return None

        return VirusTotalInfo(nb_malicious, nb_suspicious, reputation,
                              harmless_votes, malicious_votes)

    def ip_quality_score_stats(self) -> IpQualityScoreInfo:
        """
        Call IpQualityScore API to get information
        """
        if self.ipqualityscore_api_key is None:
            return None

        try:
            url = "https://ipqualityscore.com/api/json/ip/" + \
                self.ipqualityscore_api_key+"?ip="+format(self.ip)
            response = requests.get(url)
            res = json.loads(response.text)
            if res["success"] == True:
                fraud_score = res["fraud_score"]
                bot_activity = res["bot_status"]
                vpn_status = res["vpn"]
                proxy_status = res["proxy"]
                tor_status = res["tor"]
            else:
                return None
        except Exception as e:
            print("IpQualityScore error: {}".format(e), file=sys.stderr)
            return None

        return IpQualityScoreInfo(fraud_score, bot_activity, vpn_status, proxy_status, tor_status)

    def shodan_stats(self) -> ShodanInfo:
        """
        Call Shodan API to get information
        """

        if self.shodan_api_key is None:
            return None
        try:
            host = self.shodan_api.host(format(self.ip))
        except shodan.APIError as e:
            print("Shodan error: {}".format(e), file=sys.stderr)
            return None

        return ShodanInfo(len(host['data']))


def is_ip_v4_valid_ip_address(ip_addr):
    """
    Check the validity of IP V4 address
    Should be composed of 4 bytes between 0 and 255
    Return True if ip_addr is a valid IP V2 address
    """
    ip_addr_splitted = ip_addr.split(".")
    if len(ip_addr_splitted) != 4:
        return False
    try:    
        if ((not 0 <= int(ip_addr_splitted[0]) <= 255)
            or (not 0 <= int(ip_addr_splitted[1]) <= 255)
                or (not 0 <= int(ip_addr_splitted[2]) <= 255)
                or (not 0 <= int(ip_addr_splitted[3]) <= 255)):
            return False
    except Exception as e:
        print("IP format error: {}".format(e), file=sys.stderr)
        return False

    return True


def process_ip_address(ip_arg) -> DisplayIpReputationElements:
    """
    Check reputation of IP address
    Based on Shodan, VirusTotal and IpQualityScore databases
    Argument : ip_arg should be a valid IP V4 address
    Return : list of information to display on this IP
    """
    if is_ip_v4_valid_ip_address(ip_arg):
        ip_address_to_check = ipaddress.IPv4Address(ip_arg)
        ip_address_info = IpAddressCheckReputation(ip_address_to_check)
        if not ip_address_to_check.is_private:
            # Shodan infomation
            shodan_info = ip_address_info.shodan_stats()
            # ApiVoid information
            apivoid_info = ip_address_info.apivoid_stats()
            # VirusTotal information
            vt_info = ip_address_info.virustotal_stats()
            # IpQualityScore information
            ip_qual_info = ip_address_info.ip_quality_score_stats()
            return DisplayIpReputationElements(ip_address_to_check, ip_address_to_check.is_private,
                                           shodan_info, vt_info, ip_qual_info, apivoid_info)
        else:
            return DisplayIpReputationElements(ip_address_to_check, ip_address_to_check.is_private,
                                           None, None, None, None)
    else:
        return None


def main():
    """
    Check IP reputation of all IP addresses provided in stdin
    Based on Shodan, VirusTotal and IpQualityScore databases
    """
    load_dotenv()

    stdin_lines = []

    # Put IP addresses from stdin in stdin_lines list
    for line in sys.stdin:
        if line.rstrip() != "":
            ip = line.strip()
            if ip not in stdin_lines:
                stdin_lines.append(ip)
        else:
            break

    # Display IP addresses reputation information
    for ip_addr in stdin_lines:
        res = process_ip_address(ip_addr)
        if  res is not None:
            res.display_IpReputationElements()


if __name__ == '__main__':
    main()

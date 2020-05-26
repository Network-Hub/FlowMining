# -*- coding: utf-8 -*-
from io import StringIO
from scapy.all import *
import numpy as np
import re


class Capturing(list):
    """
    #this class reference to :http://cn.voidcc.com/question/p-dtimlaql-pu.html ,(available at 2020-1-5)#
    This class will capture sys.out.
    More info:
    http://stackoverflow.com/questions/16571150/how-to-capture-stdout-output-from-a-python-function-call
    """

    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self

    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        del self._stringio  # free up some memory
        sys.stdout = self._stdout


class PacketDict(dict):
    """
    #this class reference to :http://cn.voidcc.com/question/p-dtimlaql-pu.html ,(available at 2020-1-5)#
    This class will convert packet into a dict by using the result of packet.show2(). Furthermore the original
    packet will be also saved as attribute '.packet'.
    More class functions could be added, currently only support 'haslayer()'.
    Scapy version: scapy-2.3.3
    """

    def __init__(self, pkt):
        self.packet = pkt
        self.__packet_to_dict()

    def __extract_key(self, line):
        a = line.lstrip("###[ ").rstrip(" ]### ")
        return a

    def __extract_value_to_dict(self, line):
        if line.find("=") > -1:
            b = line.replace(" ", "")
            a = b.split("=")
            return {a[0]: a[1]}
        return {line.replace(" ", ""): None}

    def __packet_to_dict(self):
        with Capturing() as packet_in_list:
            self.packet.show2()
        current_dict = self
        for line in packet_in_list:
            if line.strip() != "":
                line = line.replace("|", "")
                if line.find('###[') > -1:
                    key = self.__extract_key(line)
                    current_dict[key] = {}
                    current_dict = current_dict[key]
                    continue
                current_dict.update(self.__extract_value_to_dict(line))

    def haslayer(self, pkt_cls):
        return self.packet.haslayer(pkt_cls)


class Parser:
    """
    #This class is write by jeff scott form PCL at 2020-1-10.#
    """
    protocol_num_to_letter = {'17': 'UDP', '6': 'TCP', '4': 'IPv4', '9': 'IGP', '-1': 'NULL'}
    protocol_letter_to_num = {'UDP': '17', 'TCP': '6', 'IPv4': '4', 'IGP': '9', 'NULL': '0'}

    @staticmethod
    def parse_str(string):
        """
        split the string by character and transform to integer,the character that is
        not the alpha will be removed.
        :param string: string
        :return: list , int
        """
        num_array = np.array([])
        str_list = list(str(string))
        for c in str_list:
            if re.match("[a-z]|[A-Z]", c):
                num_array = np.concatenate((num_array, [ord(c.upper()) - ord('A')]))
            else:
                pass
        return num_array

    @staticmethod
    def regularize_number(item):
        """
        transform the item into hexadecimal like "0xff"
        :param item:
        :return:
        """
        item = "".join(filter(str.isalnum, item))  # remove the non-number and non-alpha
        item = re.sub(r'[g-z]|[G-Z]', "", item)  # remove the illegal alpha except for (a-f,A-F)
        if 2 < len(item):
            item = item[:2]
        elif 0 == len(item):
            item = "00"
        else:
            item = "0" + item
        item = "0x" + item
        return item

    @staticmethod
    def parse_num(number):
        """
        if the number is bigger than 255, split the number by mod 255
        :param number: int
        :return: list , the decimal number form 0 to 255
        """
        num_array = np.array([])
        number = int(number)
        if number // 255 > 0:
            np.concatenate((num_array, [255]))
            number = number // 255
        np.concatenate((num_array, [number % 255]))
        return num_array

    def parse_binary(self, bin_object):
        """
        transfer the str to list with number
        :param bin_object:
        :return: narray (int)
        """
        num_array = np.array([])
        bin_list = str(bin_object).split("\\")
        for item in bin_list:
            if item == 'n' or item == 'b\'':
                pass
            else:
                item = self.regularize_number(item)
                # need to be tested which is more efficient
                # if num_array.size == 0:
                #     num_array = np.array([int(item, 16)])
                # num_array = np.concatenate(num_array, np.array([int(item, 16)]))
                num_array = np.concatenate((num_array, [int(item, 16)]))
        return num_array

    def parse_hex(self, hexadecimal):
        """
        parse the hexadecimal into digit
        :param hexadecimal: the hexadecimal number
        :return: list , the decimal number form 0 to 255
        """
        decimal = int(str(hexadecimal), 16)
        hex_list = self.parse_num(decimal)

        return hex_list

    @staticmethod
    def parse_ip_address(ip_address):
        """
         parse the ip address into  list by split
        :param ip_address: string
        :return: list , the byte by split the ip address
        """
        ip_address_list = [int(i) for i in str(ip_address).split(".")]
        return np.array(ip_address_list)

    def parse_mac_address(self, mac_address):
        """
         parse the mac address into  list by split
        :param mac_address: string
        :return: list , the byte by split the mac address
        """
        mac_address_list = []
        for i in str(mac_address).split(":"):
            mac_address_list.extend(self.parse_hex(i))

        return np.array(mac_address_list)

    def parse_item(self, item):
        """
        parse item according to the type
        :param item: object , the type is uncertain
        """
        if type(item) == int:
            return self.parse_num(item)
        elif type(item) == str:
            return self.parse_str(str)
        else:
            return np.array([])

    # 估计又要进行字符串的解析来获取关键字
    @staticmethod
    def parse_mysummary(mysummary):
        """
        parse the mysummary object to item
        :param mysummary: object
        :return: list
        """

        mysummary_array = np.array([])

        return mysummary_array

    def parse_options(self, options, protocol):
        """
         parse the options object to item
        :param protocol: string , like "UDP"
        :param options: list , the item is the tuple, like [('MSS', 1460), ('NOP', None), ('WScale', 8), ]
        :return:narray
        """
        options_array = np.array([])
        if options is None:
            return options_array
        elif protocol == 'TCP':
            for tup in options:
                if tup[1] is not None:
                    options_array = np.concatenate((options_array, self.parse_item(tup[1])))
                else:
                    options_array = np.concatenate((options_array, [0]))
        elif protocol == 'UDP':
            options_array = np.concatenate((options_array, self.parse_str(options)))
        elif protocol == 'IP':
            options_array = np.concatenate((options_array, self.parse_str(options)))
        else:
            pass
        return options_array

    # this function still has bug, we cannot get the pkt.DHCP
    @staticmethod
    def parse_dhcp(pkt):
        """
        parse the dhcp layer by by getting the attribute value respectively
        :param pkt: object ,the packet object like b'\x00P\xc0\xd1\xe4\xc5<m\x1b\xf0\x05\x94'
        :return: list , the attribute value of the dhcp
        """
        options_array = np.array([])
        if pkt.haslayer('DHCP'):
            options_str = re.sub("\[|\]", "", str(pkt.DHCP))
            options = options_str.split(" ")
            for item in options:
                if re.match("=", item):
                    options_array = np.concatenate((options_array, item.split("=")))
        else:
            pass
        # print("dhcp:", options_list)
        return options_array

    def parse_bootp(self, pkt):
        """
        parse the bootp layer by getting the attribute value respectively
        :param pkt: object , the packet object like b'\x00P\xc0\xd1\xe4\xc5<m\x1b\xf0\x05\x94'
        :return: list , the attribute value of the bootp
        """
        bootp_array = np.array([])
        if pkt.haslayer('BOOTP'):
            bootp_array = np.concatenate((bootp_array, self.parse_str(pkt.op)))
            bootp_array = np.concatenate((bootp_array, self.parse_num(pkt.htype)))
            bootp_array = np.concatenate((bootp_array, self.parse_num(pkt.hlen)))
            bootp_array = np.concatenate((bootp_array, self.parse_num(pkt.hops)))
            bootp_array = np.concatenate((bootp_array, self.parse_num(pkt.xid)))
            bootp_array = np.concatenate((bootp_array, self.parse_str(pkt.flags)))
            bootp_array = np.concatenate((bootp_array, self.parse_ip_address(pkt.ciaddr)))
            bootp_array = np.concatenate((bootp_array, self.parse_ip_address(pkt.yiaddr)))
            bootp_array = np.concatenate((bootp_array, self.parse_ip_address(pkt.siaddr)))
            bootp_array = np.concatenate((bootp_array, self.parse_ip_address(pkt.giaddr)))
            bootp_array = np.concatenate((bootp_array, self.parse_binary(pkt.chaddr)))
            bootp_array = np.concatenate((bootp_array, self.parse_binary(pkt.sname)))
            bootp_array = np.concatenate(
                (bootp_array, self.parse_binary(pkt.file)))  # file will be look as the payload?
            bootp_array = np.concatenate((bootp_array, self.parse_options(pkt.options, 'UDP')))
        # print("bootp:", bootp_list)
        return bootp_array

    def parse_tcp_layer(self, pkt):
        """
         parse the udp layer by getting the attribute value respectively
        :param pkt: object , like b'\x00P\xc0\xd1\xe4\xc5<m\x1b\xf0\x05\x94'
        :return: list, the attribute value of the tcp
        """
        tcp_layer = np.array([])
        if pkt.haslayer('TCP'):
            data = pkt.getlayer('TCP')
            tcp_layer = np.concatenate((tcp_layer, self.parse_num(data.sport)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_num(data.dport)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_num(data.seq)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_num(data.ack)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_num(data.dataofs)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_num(data.reserved)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_num(data.window)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_hex(data.chksum)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_hex(data.urgptr)))
            tcp_layer = np.concatenate((tcp_layer, self.parse_options(data.options, 'TCP')))
        # print("tcp:", tcp_layer)
        return tcp_layer

    def parse_udp_layer(self, pkt):
        """
         parse the udp layer by getting the attribute value respectively
        :param pkt: object , like b'\x00P\xc0\xd1\xe4\xc5<m\x1b\xf0\x05\x94'
        :return: list , the attribute value of the udp
        """
        udp_layer = np.array([])
        if pkt.haslayer('UDP'):
            data = pkt.getlayer('UDP')
            udp_layer = np.concatenate((udp_layer, self.parse_str(data.sport)))
            udp_layer = np.concatenate((udp_layer, self.parse_str(data.dport)))
            udp_layer = np.concatenate((udp_layer, self.parse_num(data.len)))
            udp_layer = np.concatenate((udp_layer, self.parse_hex(data.chksum)))
        # print("udp:", udp_layer)
        return udp_layer

    def parse_ip_layer(self, pkt):
        """
        parse the ip layer by getting the attribute value respectively
        :param pkt: object , like b'\x00P\xc0\xd1\xe4\xc5<m\x1b\xf0\x05\x94'
        :return:  list , the attribute value of the ip
        """
        ip_layer = []
        if pkt.haslayer('IP'):
            data = pkt.getlayer('IP')
            ip_layer = np.concatenate((ip_layer, self.parse_num(data.version)))
            ip_layer = np.concatenate((ip_layer, self.parse_num(data.ihl)))
            ip_layer = np.concatenate((ip_layer, self.parse_num(data.len)))
            ip_layer = np.concatenate((ip_layer, self.parse_hex(data.tos)))
            ip_layer = np.concatenate((ip_layer, self.parse_num(data.id)))
            ip_layer = np.concatenate((ip_layer, self.parse_str(data.flags)))
            ip_layer = np.concatenate((ip_layer, self.parse_num(data.frag)))
            ip_layer = np.concatenate((ip_layer, self.parse_num(data.ttl)))
            ip_layer = np.concatenate((ip_layer, self.parse_num(data.proto)))  # data.proto is number
            ip_layer = np.concatenate((ip_layer, self.parse_hex(data.chksum)))
            ip_layer = np.concatenate((ip_layer, self.parse_ip_address(data.src)))
            ip_layer = np.concatenate((ip_layer, self.parse_ip_address(data.dst)))
            ip_layer = np.concatenate((ip_layer, self.parse_options(data.options, 'IP')))
        # print("ip:", ip_layer)
        return ip_layer

    def parse_eth_layer(self, pkt):
        """
         parse the Ethernet layer by getting the attribute value respectively
        :param pkt: object , like b'\x00P\xc0\xd1\xe4\xc5<m\x1b\xf0\x05\x94'
        :return: list , the attribute value of the Ethernet
        """
        ethernet_layer = np.array([])
        if pkt.haslayer('Ethernet'):
            data = pkt.getlayer('Ethernet')
            ethernet_layer = np.concatenate((ethernet_layer, self.parse_mac_address(data.dst)))
            ethernet_layer = np.concatenate((ethernet_layer, self.parse_mac_address(data.src)))
            ethernet_layer = np.concatenate((ethernet_layer, self.parse_num(data.type)))  # data.type is number
        # print("ethernet:", ethernet_layer)
        return ethernet_layer

    def parse_header(self, pkt):
        """
        :param pkt: object , like b'\x00P\xc0\xd1\xe4\xc5<m\x1b\xf0\x05\x94'
        :return: list,  the attribute value of the whole header
        """
        header = np.array([])
        header = np.concatenate((header, self.parse_eth_layer(pkt)))
        header = np.concatenate((header, self.parse_ip_layer(pkt)))
        header = np.concatenate((header, self.parse_tcp_layer(pkt)))
        header = np.concatenate((header, self.parse_udp_layer(pkt)))
        header = np.concatenate((header, self.parse_bootp(pkt)))
        # print("header shape:", header.shape)
        return header

    @staticmethod
    def parse_payload(pkt):
        """
        :param pkt: object, like b'\x00\x0c)\x1c-#\x00\x0c)D2\xd7\x08\x00E\x00\x004\x00\x00@\x00?
        :return: list , the value of the payload
        """
        payload = np.array([])
        # print("payload shape",payload.shape)
        return payload

    @staticmethod
    def reshape_with_padding(pkt_narray, shape):
        """
         reshape the array by specified the shape,if the size of the pkt_array is smaller than
         shape, padding the pkt_array with zeros
        :param pkt_narray: narray , one dimensional list
        :param shape: list , one dimensional list
        :return: narray , 2 dimension narray with the specified shape
        """
        size = shape[0] * shape[1]
        if pkt_narray.size < size:
            for i in range(size - len(pkt_narray)):
                pkt_narray = np.append(pkt_narray, 0)
        else:
            pkt_narray = pkt_narray[:size]
        return pkt_narray.reshape(shape)

    def parse_packet(self, pkt, size):
        """
        get the narray by parser one packet
        :param size:
        :param pkt: object , like b'\x00\x0c)\x1c-#\x00\x0c)D2\xd7\x08\x00E\x00\x004\x00\x00@\x00?
        :return: narray, 3 dimension narray with shape like 1*n*m
        """
        reshape_size = tuple([1] + size)
        header = self.parse_header(pkt)  # header is an one array
        payload = self.parse_payload(pkt)  # payload is an one array
        pkt = np.concatenate((header, payload))
        packet_array = self.reshape_with_padding(pkt, size)  # reshape to 2 dimension from 1

        return packet_array.reshape(reshape_size)  # reshape to 3 dimension from 2

    def parse_flow(self, flow_pcap_path, img_size, pkt_num):
        """
        parse the pcap file as one flow with many packets
        :param img_size:
        :param flow_pcap_path: absolute path, the
        :return: narray, three dimensional narray like shape([n,m,l]),each packet is an matrix.
        """
        flow_array = np.array([])
        packets = rdpcap(flow_pcap_path)
        for i in range(min(pkt_num, len(packets))):
            if flow_array.size == 0:
                flow_array = self.parse_packet(packets[i], img_size)
            else:
                flow_array = np.concatenate((flow_array, self.parse_packet(packets[i], img_size)))
        return flow_array


class RawPcap:
    @staticmethod
    def process_packet(pkt, mat_size):
        """
        process the pkt by the binary
        :param mat_size: list , like [28, 28]
        :param pkt: object , pkt object
        :return: narray, 3 dimension narray with shape like 1*n*m
        """
        reshape_size = tuple([1] + mat_size)
        parser = Parser()
        packet_list = parser.parse_binary(pkt)
        packet_narray = parser.reshape_with_padding(packet_list, mat_size)

        return packet_narray.reshape(reshape_size)

    def process_pcap(self, pcap_file, mat_size, pkt_num):
        """
        process the pcap file into three dimension narray, each packet is an two dimension narray
        :param pkt_num: int ,cut how much number packets
        :param mat_size: array, the cut size for each packets
        :param pcap_file: a pcap file path
        :return: narray, three dimensional narray like shape([n,m,l]),each packet is an matrix.
        """

        packet_list = rdpcap(pcap_file)
        flow_narray = np.array([])
        for i in range(min(pkt_num, len(packet_list))):
            if flow_narray.size == 0:
                flow_narray = self.process_packet(packet_list[i], mat_size)
            else:
                flow_narray = np.concatenate((flow_narray, self.process_packet(packet_list[i], mat_size)))
        # print("flow_narray shape:", flow_narray.shape)
        return flow_narray

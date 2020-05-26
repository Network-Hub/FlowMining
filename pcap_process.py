# -*- coding: utf-8 -*-
import os
import pandas as pd
import numpy as np
import platform

# # 要跟pkt2flow的结果保持一致
protocol_num_to_letter = {'17': 'UDP', '6': 'TCP', '4': 'OTHERS', '9': 'OTHERS', '-1': 'OTHERS', '0': 'OTHERS'}
protocol_to_upper = dict(tcp_ip="TCP", udp_ip="UDP", ip="OTHERS", icmp_ip="OTHERS", igmp="OTHERS", ipv6icmp="OTHERS")


# protocol_letter_to_num = {'UDP': '17', 'TCP': '6', 'IPv4': '4', 'IGP': '9', 'NULL': '0'}


def get_files_hierarchically(dir_path):
    """
     get the files hierarchically under the folder
    :param dir_path: absolute path
    :return: narray , the item is the files with absolute path
    """
    files = np.array([])
    for home, dir_list, file_list in os.walk(dir_path):
        for filename in file_list:
            files = np.concatenate((files, [os.path.join(home, filename)]))
            # files.append(os.path.join(home, filename))
    print("get %d files" % (len(files)))
    return files


def split_file_path(path):
    if platform.system() == "Windows":
        path_list = path.split("\\")
    elif platform.system() == "Linux":
        path_list = path.split("/")
    else:
        print("System incompatibility")
        exit(1)
    return path_list


def join_file_path(path_list):
    if platform.system() == "Windows":
        path = "\\".join(path_list)
    elif platform.system() == "Linux":
        path = "/".join(path_list)
    else:
        print("System incompatibility")
        exit(1)
    return path


def get_filename_without_suffix(path):
    """
     get a filename without the suffix ".pcap"
    :param path: absolutely path , like D:\\dataHub\\botnet.pcap.TCP_10-10-10-132_4444_192-168-1-101_49356.pcap
    :return: a string , like botnet.pcap.TCP_10-10-10-132_4444_192-168-1-101_49356
    """
    filename = split_file_path(path)[-1]
    filename = filename.replace(".pcap", "")
    filename = filename.replace(".npz", "")
    return filename


def get_csv_info(path, data_set_type):
    """
     read the ground truth information from the csv file by the official document
    :param data_set_type: int, 0: NDSec-1, 1: CIC-IDS-2017, 2: ISCXIDS2012 3:SCXIDS2012 monday 4: CICDoS2017
    :param path: absolutely path , like D:\\dataHub\\gt.csv
    :return: Numpy.DataFrame
    """
    df = pd.read_csv(path)
    if data_set_type == 0:
        # concatenate the protocol,srcip,srcoport,dstip,dstport into one column as index
        df['protocol'] = df['protocol'].map(lambda x: protocol_num_to_letter[str(x)])
        df['index'] = df['protocol'].map(str) + '_' + df['srcip'].map(str) + '_' + df['srcport'].map(str) + '_' + df[
            'dstip'].map(str) + '_' + df['dstport'].map(str)
    elif data_set_type == 1:
        df.columns = range(len(df.columns.values.tolist()))
        df[5] = df[5].map(lambda x: protocol_num_to_letter[str(x)])  # 要跟pkt2flow的结果保持一致
        df['index'] = df[5].map(str) + '_' + df[1].map(str) + '_' + df[2].map(
            str) + '_' + df[3].map(str) + '_' + df[4].map(str)
        df['label'] = df[84]
    elif data_set_type == 2:
        df.columns = range(len(df.columns.values.tolist()))
        df[14] = df[14].map(lambda x: protocol_to_upper[str(x)])
        df['index'] = df[14].map(str) + '_' + df[13].map(str) + '_' + df[15].map(
            str) + '_' + df[16].map(str) + '_' + df[17].map(str)
        df['label'] = df[20]
    elif data_set_type == 3:
        df.columns = range(len(df.columns.values.tolist()))
        df[13] = df[13].map(lambda x: protocol_to_upper[str(x)])
        df['index'] = df[13].map(str) + '_' + df[12].map(str) + '_' + df[14].map(
            str) + '_' + df[15].map(str) + '_' + df[16].map(str)
        df['label'] = df[19]
    elif data_set_type == 4:
        df.columns = range(len(df.columns.values.tolist()))
        df['index'] = df[0].map(str)
        label = []
        for i in range(df['index'].shape[0]):
            label.append("DoS")
        df['label'] = pd.Series(label)
    else:
        print("None support for this dataset!")
        exit(1)
    # path = os.getcwd()
    csv_dir = get_dir_from_path(path)
    df.to_csv(csv_dir + "/index.csv")
    print("> index.csv saved in " + csv_dir + " successfully!")
    # 只保留索引和
    index_df = pd.DataFrame(df['index'])
    index_df['label'] = df['label']
    # 垃圾回收
    del df
    return index_df


def get_label(index_name, df):
    """
    get the label by index the DataFrame
    :param index_name: string , the key for index from the processed filename
    :param df: DataFrame , with the column df['index'] created by get_csv_info(path)
    :return: string, the label ATTACK or NORMAL
    """
    label = df[df['index'] == index_name]['label'].values
    if len(label) == 0:  # mismatch will set as NULL
        label = 'NULL'
    else:
        label = label[0]
    if label != 'NULL':
        print(index_name, label)
    return label


def make_dir(new_dir_path):
    """
    create the new directory if it not exist
    :param new_dir_path: absolutely path , the new directory
    :return: absolutely path
    """
    if os.path.exists(new_dir_path):
        pass
    else:
        os.makedirs(new_dir_path)

    return new_dir_path


def get_filename_with_suffix(path):
    """
     get a filename with the suffix ".pcap"
    :param path: absolutely path , like D:\\dataHub\\botnet.pcap.TCP_10-10-10-132_4444_192-168-1-101_49356.pcap
    :return: string , like botnet.pcap.TCP_10-10-10-132_4444_192-168-1-101_49356.pcap
    """
    filename = split_file_path(path)[-1]
    return filename


def get_dir_from_path(path):
    """
    get a path exclude the filename
    :param path: absolutely path, like D:\\dataHub\\botnet.pcap.TCP_10-10-10-132_4444_192-168-1-101_49356.pcap
    :return: string, like D:\\dataHub
    """
    path = split_file_path(path)[:-1]
    if platform.system() == "Windows":
        dir_path = join_file_path(path)
    elif platform.system() == "Linux":
        dir_path = "/".join(path)
    else:
        print("System incompatibility")
        exit(1)

    return dir_path


def get_index_name_pkg2flow(filename, file_dir):
    """
    get the index_name for get_label(index_name, df) by process the filename;
    the raw pcap file is split into flow based pcap by a tool called pkg2flow.
    :param filename: string , like  10.10.10.132_4444_192.168.1.101_49356_1459503779.pcap
    :param file_dir: absolute path, exclude the filename with suffix like  D:\\dataHub
    :return: string , like tcp_10.10.10.132_4444_192.168.1.101_49356; it is the five tuple
    ( protocol,src_ip,src_port,dst_ip,dst_port)
    """
    file_dir = split_file_path(file_dir)[-1]
    dir_name = file_dir.split("_")[0]
    filename = filename.split("_")[:-1]
    filename = "_".join(filename)
    index_name = dir_name.upper() + "_" + filename
    return index_name


def get_index_name_splitcap(filename):
    """
    get the index_name for get_label(index_name, df) by process the filename;
    the raw pcap file is split into flow based pcap by a tool called SplitCap.
    :param filename: string , like  botnet.pcap.TCP_2-16-181-11_80_192-168-1-109_49289.pcap
    :return: string , like tcp_10.10.10.132_4444_192.168.1.101_49356; it is the five tuple
    ( protocol,src_ip,src_port,dst_ip,dst_port)
    """
    filename = filename.split('.')
    filename = filename[-2]
    index_name = filename.replace('-', '.')
    return index_name


def get_index_name_DoS(filename):
    filename = filename.split('_')
    return filename[2]


def classify_file_from_pkt2flow(directory, csv_path, data_set_type):
    """
     classify the files from the target directory by the label of them.
    :param data_set_type: int, 0: NDSec-1, 1: CIC-IDS-2017, 2:CIC-DDoS2019
    :param directory: absolute path, exclude the filename with suffix like  D:\\dataHub
    :param csv_path: absolutely path , like D:\\dataHub\\gt.csv
    """
    file_list = get_files_hierarchically(directory)  # get the files path list
    df = get_csv_info(csv_path, data_set_type)  # get the DataFrame
    for file_path in file_list:
        filename = get_filename_with_suffix(file_path)  # get filename
        file_dir = get_dir_from_path(file_path)  # get the present directory
        index_name = get_index_name_pkg2flow(filename, file_dir)  # get the index name
        label = get_label(index_name, df)  # get the label
        new_dir = make_dir(file_dir + os.sep + label)  # make new directory with label
        new_name = new_dir + os.sep + label + '_' + index_name + filename.split("_")[-1]
        os.rename(file_path, new_name)
    print("> files labeled success!")


# the source filename format is : botnet.pcap.TCP_2-16-181-11_80_192-168-1-109_49289    # by SplitCap
def classify_file_from_splitcap(directory, csv_path, data_set_type):
    """
     classify the files from the target directory by the label of them.
    :param directory: absolute path, exclude the filename with suffix like  D:\\dataHub
    :param csv_path: absolutely path , like D:\\dataHub\\gt.csv
    """
    file_list = get_files_hierarchically(directory)  # get the files path list
    df = get_csv_info(csv_path, data_set_type)  # get the DataFrame
    for file_path in file_list:
        filename = get_filename_with_suffix(file_path)  # get filename
        file_dir = get_dir_from_path(file_path)  # get the present directory
        index_name = get_index_name_splitcap(filename)  # get the index name
        label = get_label(index_name, df)  # the file is with
        new_dir = make_dir(file_dir + os.sep + label)  # make new directory with label
        new_name = new_dir + os.sep + label + '_' + filename
        os.rename(file_path, new_name)


def classify_DoS(directory, csv_path):
    file_list = get_files_hierarchically(directory)  # get the files path list
    df = get_csv_info(csv_path, 4)  # get the DataFrame
    for file_path in file_list:
        filename = get_filename_with_suffix(file_path)  # get filename
        file_dir = get_dir_from_path(file_path)  # get the present directory
        print("file_dir =", file_dir)
        index_name = get_index_name_DoS(filename)  # get the index name
        label = get_label(index_name, df)  # the file is with
        new_dir = make_dir(file_dir + os.sep + label)  # make new directory with label
        new_name = new_dir + os.sep + label + '_' + filename
        os.rename(file_path, new_name)


def split_pcap(file_dir):
    """
     split the big pcap file into small one based on session. this function is based on the
     tool named SplitCap. So make sure the SplitCap packet has been put under the same folder of this file.
     This tool only fits the Windows system.you can get from https://www.netresec.com/?page=SplitCap
    :param file_dir: absolute path, exclude the filename with suffix like  D:\\dataHub
    """
    file_list = os.listdir(file_dir)
    for file in file_list:
        if file.endswith(".pcap"):
            filename = file.split(".")[0]
            new_dir = make_dir(file_dir + os.sep + 'split' + os.sep + filename)
            pwd = os.getcwd()
            cmd = pwd + os.sep + "SplitCap\\SplitCap" + " -r " + file_dir + os.sep + file + " -o " + new_dir
            os.popen(cmd)


def pkt2flow(file_dir, tool_home_dir):
    """
     split the big pcap file into small one based on session. this function is based on the
     tool named pkt2flow. So make sure you have have install the support tool firstly.
     This tool fits the Linux system.you can get it from https://github.com/caesar0301/pkt2flow
    :param tool_home_dir: absolute path, the home directory of pkt2flow
    :param file_dir: absolute path, exclude the filename with suffix like  /home/god/dataHub
    """
    file_list = os.listdir(file_dir)
    for file in file_list:
        if file.endswith(".pcap"):
            filename = file.split(".")[0]
            new_dir = make_dir(file_dir + os.sep + 'split' + os.sep + filename)
            cmd = tool_home_dir + os.sep + "pkt2flow" + " -uvx " + " -o " + new_dir + file_dir + os.sep + file
            os.popen(cmd)

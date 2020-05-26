# -*- coding: utf-8 -*-
from pcap_process import *
from pcap_parser import *
from scapy.all import *
from scipy import stats
from PIL import Image
import time
import matplotlib.pyplot as plt
import gc
import sys


def get_packets(pcap_file):
    """
    get the the packet objects
    :param pcap_file: the pcap file path
    :return: list, the packet objects
    """
    packets = rdpcap(pcap_file)
    return packets


def get_label_from_filename(filename):
    """
    get label by clip the filename
    :param filename: absolute path ,the filename of the pcap file
    :return: string ,the label such as ATTACK
    """
    label = split_file_path(filename)[-1]
    label = label.split("_")[0]
    # 正常用0表示，异常流量用1表示
    if label == "NORMAL" or label == "BENIGN" or label == "Normal":
        return 0
    else:
        return 1


def packet_to_png(packet_narray, save_path):
    """
    transform one packet object into one image
    :param packet_narray: narray , the narray for the packet
    :param save_path: absolute path, the path to save the image
    :return:None
    """
    save_path = save_path + ".png"
    im = Image.fromarray(packet_narray.astype("uint8"))
    im.save(save_path)
    return


def flow_to_img(flow_pcap_path, img_size, mode):
    """
    transform one pcap file to images.since one flow is split as one pcap.so it is
     actually processing one flow. the outcome directory is in the present folder.
    :param mode: "raw" for process the raw pcap; "parser" for parse the protocol
    :param img_size: the image size you wanna generate
    :param flow_pcap_path: the pcap file
    :return:None
    """
    if mode == "raw":
        pcap_raw = RawPcap()
        packets = pcap_raw.process_pcap(flow_pcap_path, img_size)
    elif mode == "parser":
        pcap_parser = Parser()
        packets = pcap_parser.parse_flow(flow_pcap_path, img_size)
    else:
        pass
    label = get_label_from_filename(flow_pcap_path)
    i = 0
    for pkt in packets:
        dir_path = join_file_path(split_file_path(flow_pcap_path)[:-1])
        directory = make_dir(dir_path + os.sep + "images" + os.sep + get_filename_without_suffix(flow_pcap_path))
        save_path = directory + os.sep + str(label) + "_" + str(i)
        i += 1
        packet_to_png(pkt, save_path)
    return


def pcap_to_img(pcap_dir, img_size=[50, 50], mode="raw"):
    """
    transform all the pcap files in the folder into images,
    the outcome directory is in the present folder
    :param pcap_dir: absolute path
    :param img_size: list, the size of the image to generate
    :param mode:string, "raw" for process the raw pcap; "parser" for parse the protocol
    :return: None
    """
    file_list = get_files_hierarchically(pcap_dir)
    for file in file_list:
        flow_to_img(file, img_size, mode)
        print(file, " ==> images...")
    return


def flow_to_arr(flow_pcap_path, mat_size, mode, pkt_num):
    """
     transfer the flow into npy
    :param flow_pcap_path: absolute path, a pcap file
    :param mat_size: list, the matrix size for the packet
    :param mode: string, "raw" or "parser"
    :return: narray, two, the x contains the matrix and the y contains the label
    """
    x, y = np.array([[]]), np.array([])
    if mode == "raw":
        pcap_raw = RawPcap()
        packets = pcap_raw.process_pcap(flow_pcap_path, mat_size, pkt_num)
    else:
        pcap_parser = Parser()
        packets = pcap_parser.parse_flow(flow_pcap_path, mat_size, pkt_num)
    x = packets  # three dimensional narray like shape([n,m,l]),each packet is an matrix.
    label = get_label_from_filename(flow_pcap_path)
    if label == 1:  # each flow an label
        y = np.append(y, np.ones(packets.shape[0]))
    else:
        y = np.append(y, np.zeros(packets.shape[0]))
    print(get_filename_with_suffix(flow_pcap_path) + "  processed success!" + " label:", label)
    return x, y


def pcap_to_split_npz(file_list, save_path, mat_size, mode, pkt_num):
    for file in file_list:
        x_tmp, y_tmp = flow_to_arr(file, mat_size, mode, pkt_num)
        filename = get_filename_without_suffix(file)
        np.savez(save_path + os.sep + filename + ".npz", x=x_tmp, y=y_tmp)  # (47157, 32, 32)
    return


def pcap_to_npz(file_list, save_path, mat_size, mode):
    """
     transfer the given file in the file_list into npz
    :param file_list: narray, files with absolute path
    :param save_path: absolute path,
    :param mat_size: list, the matrix size for the packet
    :param mode: string, "raw" or "parser"
    """
    x, y = np.array([]), np.array([])
    filename = get_filename_with_suffix(save_path)
    for file in file_list:
        x_tmp, y_tmp = flow_to_arr(file, mat_size, mode)
        if len(x) == 0:
            x = x_tmp  # four dimension
            y = y_tmp  #
        else:
            x = np.concatenate((x, x_tmp))
            y = np.concatenate((y, y_tmp))
    if filename == "train.npz":
        np.savez(save_path, x_train=x, y_train=y)  # (47157, 32, 32)
    elif filename == "test.npz":
        np.savez(save_path, x_test=x, y_test=y)
    else:
        print("save filename error!")
        print(filename)
        exit(1)
    print("x_shape :", x.shape, "y_shape :", y.shape, ">")


def flow_to_npz(file_list, save_dir, mat_size, pkt_num, mode):
    for file in file_list:
        filename = get_filename_without_suffix(file)
        x, y = flow_to_arr(file, mat_size, pkt_num, mode)
        np.savez(save_dir + os.sep + filename + ".npz", x_train=x, y_train=y)
        print("x_shape :", x.shape, "y_shape :", y.shape, ">")
    return


def generate_npz_dataset(pcap_dir, save_dir, mat_size=[32, 32], pkt_num=30, mode="raw", split_ratio=0.6):
    """
    get the pcap files under the folder and transfer to .npz file
    :param pkt_num:
    :param save_dir: absolute path, folder for the outcome
    :param pcap_dir: absolute path, folder contains only the pcap files
    :param mat_size: list, the matrix size for the packet
    :param mode: string, "raw" or "parser"
    :param split_ratio: float, split the whole dataset into two part by the ratio
    :return: None
    """
    file_list = get_files_hierarchically(pcap_dir)
    files_for_train = file_list[:int(file_list.size * split_ratio)]
    files_for_test = file_list[int(file_list.size * split_ratio):]

    start = time.time()
    save_train_dir = make_dir(save_dir + os.sep + "train")
    flow_to_npz(files_for_train, save_train_dir, mat_size, pkt_num, mode)

    save_test_dir = make_dir(save_dir + os.sep + "test")
    flow_to_npz(files_for_test, save_test_dir, mat_size, pkt_num, mode)
    end = time.time()
    print("time cost:", (end - start) / 60, "min")

    return


def generate_npz_files(pcap_dir, save_dir, mat_size, mode="raw"):
    """
    get the pcap files under the folder and transfer to .npz file
    :param save_dir: absolute path, folder for the outcome
    :param pcap_dir: absolute path, folder contains only the pcap files
    :param mat_size: list, the matrix size for the packet
    :param mode: string, "raw" or "parser"
    :return: None
    """
    file_list = get_files_hierarchically(pcap_dir)
    start = time.time()
    save_train_dir = make_dir(save_dir)
    flow_to_npz(file_list, save_train_dir, mat_size, mode)
    end = time.time()
    print("time cost:", (end - start) / 60, "min")

    return


def generate_split_npz_dataset(pcap_dir, save_dir, mat_size, pkt_num, mode="raw", split_ratio=0.6):
    """
    get the pcap files under the folder and transfer to .npz file
    :param pkt_num:
    :param save_dir: absolute path, folder for the outcome
    :param pcap_dir: absolute path, folder contains only the pcap files
    :param mat_size: list, the matrix size for the packet
    :param mode: string, "raw" or "parser"
    :param split_ratio: float, split the whole dataset into two part by the ratio
    :return: None
    """
    file_list = get_files_hierarchically(pcap_dir)
    files_for_train = file_list[:int(file_list.size * split_ratio)]
    files_for_test = file_list[int(file_list.size * split_ratio):]

    start = time.time()
    save_train_dir = make_dir(save_dir + os.sep + "train")
    pcap_to_split_npz(files_for_train, save_train_dir, mat_size, mode, pkt_num)
    save_test_dir = make_dir(save_dir + os.sep + "test")
    pcap_to_split_npz(files_for_test, save_test_dir, mat_size, mode, pkt_num)
    end = time.time()
    print("time cost:", (end - start) / 60, "min")

    return


def compress_npz(file_dir, pkt_num):
    files = get_files_hierarchically(file_dir)
    for file in files:
        packets = np.load(file)
        x_tmp = packets['x'][:pkt_num]
        y_tmp = packets['y'][:pkt_num]
        np.savez(file, x=x_tmp, y=y_tmp)
    filename = get_filename_without_suffix(file_dir)
    print(filename, "compressed success!")
    return


def compress_dataset(file_dir, pkt_num):
    # train_npz_list = file_dir + os.sep + "train"
    # test_npz_list = file_dir + os.sep + "test"
    # compress_npz(train_npz_list, pkt_num)
    compress_npz(file_dir, pkt_num)
    print("compress dataset success!")
    return


"""
the following is to analysize the statistic of the dataset
"""


def plot_bar(name_list, num_list, x_label, y_label):
    # plt.switch_backend('agg')
    plt.rcParams['font.sans-serif'] = ['SimHei']  # 设置字体以便支持中文
    # 'family': 'Times New Roman',
    font = {
        'weight': 'normal',
        'size': 18,
    }
    save_dir = make_dir(os.getcwd() + os.sep + "figure" + os.sep)
    plt.figure(figsize=(7.5, 4.8), dpi=300)
    plt.bar(range(len(num_list)), num_list, color='rgb', tick_label=name_list)
    plt.xlabel(x_label, font)
    plt.ylabel(y_label, font)

    save_path = save_dir + os.sep + str(random.randint(0, 1000)) + "_bar.png"
    plt.savefig(save_path)
    print("bar saved in ", save_path)


def plot_pie(name_list, num_list):
    plt.switch_backend('agg')
    save_dir = make_dir(os.getcwd() + os.sep + "figure" + os.sep)
    plt.figure(figsize=(6.2, 4.8), dpi=300)
    plt.pie(num_list, labels=name_list, autopct='%.2f%%', pctdistance=0.85)
    plt.title('ratios')
    save_path = save_dir + os.sep + str(random.randint(0, 1000)) + "_pie.png"
    plt.savefig(save_path)
    print("pie saved in ", save_path)


def print_statistic(narr):
    num = len(narr)
    minimum = np.amin(narr)
    maximum = np.amax(narr)
    dif = np.ptp(narr)
    median = np.median(narr)
    mean = np.mean(narr)
    std = np.std(narr)
    variance = np.var(narr)
    mode = stats.mode(narr, axis=None)
    bin_count = np.bincount(narr.astype(int))
    print("number:", num, "min:", minimum, "max:", maximum, "dif:", dif, "median:", median, "mean:", mean, "std:", std,
          "variance:", variance, "mode:", mode)
    return bin_count


def statistic_bin_count(bin_count, start, end):
    # mode = mode[0]  # mode 是一个二元组对象
    counter = np.array([])
    rate = np.array([])
    # flag = np.amax(mode).astype(int)  # 众数可能有多个, 取最大一个作为标志
    total = np.sum(bin_count)
    # for x in mode:  # 依次遍历众数
    #     print("mode:%d  %d %.4f" % (x, bin_count[int(x)], bin_count[int(x)] / total))
    print("num\tcount\trate")
    for i in range(start, end + 1):
        if bin_count[i] != 0:
            print("%d\t%d\t%.4f" % (i, bin_count[i], bin_count[i] / total))
            counter = np.append(counter, bin_count[i])
            rate = np.append(rate, bin_count[i] / total)
    return counter, rate


def count_size_in_folder(dir_path):
    """
     统计文件夹下文件的大小信息，单位是kB
    :param dir_path:
    """
    files = get_files_hierarchically(dir_path)
    fsize_array = np.array([])
    for file in files:
        fsize_array = np.concatenate((fsize_array, [os.path.getsize(file) / 1024]))
    del files
    gc.collect()
    csv_path = dir_path + os.sep + str(random.randint(0, 1000000)) + "_fsize.csv"
    add_to_csv(csv_path, 0, fsize_array)
    print("---------the statistic of the file(flow) size in folder---------")
    print_statistic(fsize_array)
    return fsize_array


def count_flow_in_folder(dir_path):
    """
     统计每个流当中包的个数情况, 单位是个
    :param dir_path:
    """
    files = get_files_hierarchically(dir_path)
    flow_pkt_num = np.array([])
    for file in files:
        flow = rdpcap(file)
        flow_pkt_num = np.concatenate((flow_pkt_num, [len(flow)]))
        del flow
        gc.collect()
    del files
    gc.collect()
    csv_path = dir_path + os.sep + str(random.randint(0, 1000000)) + "_flow_count.csv"
    add_to_csv(csv_path, 0, flow_pkt_num)
    return flow_pkt_num


def show_flow_metric(flow_count):
    # plt.rcParams['font.sans-serif'] = ['SimHei']  # 设置字体以便支持中文
    print("---------the statistic of the each flow  in folder---------")
    bin_count = print_statistic(flow_count)
    counter_list = np.array([])
    # rate_list = np.array([])
    counter, rate = statistic_bin_count(bin_count, 0, 10)
    counter_list = np.append(counter_list, counter)
    # rate_list = np.append(rate_list, rate)
    counter, rate = statistic_bin_count(bin_count, 11, len(bin_count) - 1)
    counter_list = np.append(counter_list, np.sum(counter))
    # rate_list = np.append(rate_list, np.sum(rate))
    name_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, '>10']
    plot_bar(name_list, counter_list, x_label="流中的包个数", y_label="流的个数")
    # plot_bar(name_list, counter_list, x_label="packet count", y_label="flow number")
    plot_pie(name_list, counter_list)


def count_pkt_in_flow(dir_path):
    """
    统计所有流当中包的大小信息,大小的单位是Byte
    :param dir_path:
    """
    pkt_num = np.array([])
    files = get_files_hierarchically(dir_path)
    for file in files:
        flow = rdpcap(file)
        for pkt in flow:
            pkt_num = np.concatenate((pkt_num, [len(pkt)]))
        del flow
        gc.collect()
    del files
    gc.collect()
    csv_path = dir_path + os.sep + str(random.randint(0, 1000000)) + "_pkt_count.csv"
    add_to_csv(csv_path, 0, pkt_num)
    return pkt_num


def show_pkt_metric(pkt_count):
    print("---------the statistic of the packet in the folder---------")
    bin_count = print_statistic(pkt_count)
    counter_arr = np.array([])
    # rate_arr = np.array([])
    counter, rate = statistic_bin_count(bin_count, 60, 60)
    counter_arr = np.append(counter_arr, np.sum(counter))
    # rate_arr = np.append(rate_arr, np.sum(rate))
    counter, rate = statistic_bin_count(bin_count, 61, 100)
    counter_arr = np.append(counter_arr, np.sum(counter))
    counter, rate = statistic_bin_count(bin_count, 101, 325)
    counter_arr = np.append(counter_arr, np.sum(counter))
    counter, rate = statistic_bin_count(bin_count, 326, 485)
    counter_arr = np.append(counter_arr, np.sum(counter))
    counter, rate = statistic_bin_count(bin_count, 486, 785)
    counter_arr = np.append(counter_arr, np.sum(counter))
    counter, rate = statistic_bin_count(bin_count, 786, 1024)
    counter_arr = np.append(counter_arr, np.sum(counter))
    counter, rate = statistic_bin_count(bin_count, 1025, len(bin_count) - 1)
    counter_arr = np.append(counter_arr, np.sum(counter))
    name_list = ['60', '61-100', '101-325', '326-485', '486-785', '786-1024', '>1024']
    plot_bar(name_list, counter_arr, x_label="包的大小", y_label='包的数目')
    # plot_bar(name_list, counter_arr, x_label="packet size", y_label='packet number')
    name_list = ['60', '61-100', '101-325', '326-1024', '>1024']
    counter_arr = np.array([counter_arr[0], counter_arr[1], counter_arr[2], np.sum(counter_arr[3:5]), counter_arr[6]])
    plot_pie(name_list, counter_arr)


def add_to_csv(saved_path, col_name, arr):
    df = pd.DataFrame()
    df[col_name] = arr
    df.to_csv(saved_path)
    print("count file saved in ", saved_path)


def concat_csv(csv_dir):
    csv_files = get_files_hierarchically(csv_dir)
    save_dir = get_dir_from_path(csv_dir) + os.sep + "concat_csv.csv"
    u_df = pd.DataFrame()
    for file in csv_files:
        t_df = pd.read_csv(file, index_col=0)
        u_df = pd.concat([u_df, t_df], axis=0, ignore_index=True)
    u_df.to_csv(save_dir)
    print("concat_csv.csv saved in", save_dir)


def count_big_files():
    """
    this function must be used with the one_step.sh and process.sh
    """
    arg0 = sys.argv[1]
    count_flow_in_folder(arg0)
    count_pkt_in_flow(arg0)


def show_csv_metric(flow_csv, pkt_csv):
    df = pd.read_csv(flow_csv)
    counter = df['0'].values
    show_flow_metric(counter)
    df = pd.read_csv(pkt_csv)
    counter = df['0'].values
    show_pkt_metric(counter)


def show_pkt(pcap_path):
    pkts = rdpcap(pcap_path)
    print(pkts[0])
    print("-----------------------------------------------------")
    print(pkts[0].show())
    return

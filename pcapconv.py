# This is a sample Python script.
import io
import argparse

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
def process(path, in_addr, out_addr):
    o_path = path + '-out.pcap'
    w = open(o_path, 'wb')
    with open(path, 'rb') as file:
        file.seek(0, io.SEEK_END)
        total_size = file.tell()
        file.seek(0, io.SEEK_SET)
        pcap_global = file.read(24)
        pos = 24
        w.write(pcap_global)
        while pos < total_size:
            pcap_pkt = file.read(16)
            pos += 16
            bytes = pcap_pkt[12:15]
            w.write(pcap_pkt)
            len = int.from_bytes(bytes, byteorder='little')
            pkt = list(file.read(len))
            rs = change_addr(pkt[14:43], in_addr, out_addr)
            pkt[14+16] = rs[16]
            pkt[14+17] = rs[17]
            pkt[14+18] = rs[18]
            pkt[14+19] = rs[19]

            pkt[14+22] = rs[22]
            pkt[14+23] = rs[23]
            w.write(bytearray(pkt))
            pos += len
    w.close()
    print('close')


def change_addr(arr, in_addr, out_addr):
    tmp = in_addr.split(':')
    tmp_ip = tmp[0].split('.')
    in_ip = int(tmp_ip[0]) << 24
    in_ip += int(tmp_ip[1]) << 16
    in_ip += int(tmp_ip[2]) << 8
    in_ip += int(tmp_ip[3])
    in_udp = int(tmp[1])

    tmp = out_addr.split(':')
    tmp_ip = tmp[0].split('.')
    out_ip = int(tmp_ip[0]) << 24
    out_ip += int(tmp_ip[1]) << 16
    out_ip += int(tmp_ip[2]) << 8
    out_ip += int(tmp_ip[3])
    out_udp = int(tmp[1])

    dest_ip = arr[16:20]
    dest_udp = arr[22:24]
    curr_ip = int.from_bytes(dest_ip, byteorder='big')
    curr_udp = int.from_bytes(dest_udp, byteorder='big')
    arr = list(arr)
    if in_ip == curr_ip and in_udp == curr_udp:
        rs = out_ip.to_bytes(4, byteorder='big')
        arr[16:20] = rs
        rs = out_udp.to_bytes(2, byteorder='big')
        arr[22:24] = rs
    return arr


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument('-pcap', type=str, help='use pcap filename')
    parse.add_argument('-i', type=str, help='Source Multicast')
    parse.add_argument('-o', type=str, help='Destination Multicast')
    args = parse.parse_args()
    pcap = args.pcap
    i = args.i
    o = args.o
    if pcap is None:
        print('pcap None')
    if i is None:
        print('i None')
    if o is None:
        print('o None')
    process(pcap, i, o)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

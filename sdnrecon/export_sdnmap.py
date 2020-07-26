#pip install openpyxl
#pip install pandas

import pandas as pd
import os
import sys

def _parse_file(filepath):
    row = []
    with open(filepath, 'r') as file_object:
        line = file_object.readline()
        
        while line:
            if("match=type" not in line):
                line = file_object.readline()
                continue
            line = line.replace("arp_op=1","arp_op:1")
            line = line.replace("type:icmp,tcp","type:icmp_tcp")
            line = line.replace("type:icmp,udp","type:icmp_udp")
            line = line.replace("type:tcp,udp","type:tcp_udp")
            print(line)
            temp_row = []
            temp_actions = []
            first_parse = line.split(" ")

            second_parse = first_parse[0].split(',')

            for i in range(0,len(column)):
                check = 0
                for j in range(0,len(second_parse)):
                    if(column[i] in second_parse[j]):
                        y = second_parse[j].split(":",1)
                        temp_row.append(y[1])
                        check = 1
                        break
                if(check==1):
                    continue
                temp_row.append("")
            #temp_row = list(map(list, zip(*temp_row)))
            #print(temp_row)
            if("actions" in first_parse[1]):
                index = len(column) - 1
                temp_actions = first_parse[1].split("=")
                temp_row[index] = temp_actions[1]
            row.append(temp_row)      
            line = file_object.readline()
    return row

def main():
    global column
    if (sys.argv[1] == "icmp"):
        column = ['match=type', 'in_port', 'arp_op', 'dl_src', 'dl_dst', 'tp_src', 'tp_dst', 'nw_src', 'nw_dst', 'actions']
        path = os.getcwd()[0:(int(os.getcwd().find("sdnrecon")))]
        row = _parse_file(path + "sdnrecon/sdnmap/temp_icmp.txt")
        os.remove(path + "sdnrecon/sdnmap/temp_icmp.txt")

    elif (sys.argv[1] == "tcp"):
        column = ['match=type', 'in_port', 'arp_op', 'dl_src', 'dl_dst', 'tp_src', 'tp_dst', 'nw_src', 'nw_dst', 'actions']
        path = os.getcwd()[0:(int(os.getcwd().find("sdnrecon")))]
        row = _parse_file(path + "sdnrecon/sdnmap/temp_tcp.txt")
        os.remove(path + "sdnrecon/sdnmap/temp_tcp.txt")
    
    #print(row)
    #row.insert(0,column)
    row_dict={'match=type': [], 'in_port': [], 'arp_op': [], 'dl_src': [], 'dl_dst': [], 'tp_src': [], 'tp_dst': [], 'nw_src': [], 'nw_dst': [], 'actions': []}
    arr1,arr2,arr3,arr4,arr5,arr6,arr7,arr8,arr9,arr10=[],[],[],[],[],[],[],[],[],[]
    for r in row:
        for i in range(0,len(r)):
            if i == 0:
                arr1.append(r[0])
            if i == 1:
                arr2.append(r[1])
            if i == 2:
                arr3.append(r[2])
            if i == 3:
                arr4.append(r[3])
            if i == 4:
                arr5.append(r[4])
            if i == 5:
                arr6.append(r[5])
            if i == 6:
                arr7.append(r[6])
            if i == 7:
                arr8.append(r[7])
            if i == 8:
                arr9.append(r[8])
            if i == 9:
                arr10.append(r[9])
    row_dict['match=type'] = arr1
    row_dict['in_port'] = arr2
    row_dict['arp_op'] = arr3
    row_dict['dl_src'] = arr4
    row_dict['dl_dst'] = arr5
    row_dict['tp_src'] = arr6
    row_dict['tp_dst'] = arr7
    row_dict['nw_src'] = arr8
    row_dict['nw_dst'] = arr9
    row_dict['actions'] = arr10
    #print(row_dict)
    #Edit from here to end for exporting to Excel 
    df = pd.DataFrame(row_dict)
    #print(sys.argv[1])
    if (sys.argv[1] == "icmp"):
        filename = path + "sdnrecon/report/rule_recontruct/report_rule_recontruct_icmp.xlsx"
    elif (sys.argv[1] == "tcp"):
        filename = path + "sdnrecon/report/rule_recontruct/report_rule_recontruct_tcp.xlsx"
    df.to_excel(filename, index = False, header=True)
    print("[##] Result saved to " + "/sdnrecon/report/rule_recontruct/report_rule_recontruct_icmp.xlsx")

main()

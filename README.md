<!DOCTYPE html><html><head><meta charset="utf-8"><title>sdnrecon.md</title><style></style></head><body id="preview">
<h1 class="code-line" data-line-start=0 data-line-end=1><a id="sdnrecon_0"></a>sdnrecon</h1>
<p class="has-line-data" data-line-start="2" data-line-end="3"><a href="https://nodesource.com/products/nsolid"><img src="https://cldup.com/dTxpPi9lDf.thumb.png" alt="N|Solid"></a></p>
<p class="has-line-data" data-line-start="4" data-line-end="5"><a href="https://travis-ci.org/joemccann/dillinger"><img src="https://travis-ci.org/joemccann/dillinger.svg?branch=master" alt="Build Status"></a></p>
<h1 class="code-line" data-line-start=6 data-line-end=7><a id="sdnrecon_l_g_6"></a>sdnrecon là gì?</h1>
<p class="has-line-data" data-line-start="7" data-line-end="8">sdnrecon là một bộ công cụ phục vụ việc trinh thám mạng SDN từ nhiều vị trí khác nhau trong mạng.</p>
<h1 class="code-line" data-line-start=8 data-line-end=9><a id="iu_kin_tin_quyt_8"></a>Điều kiện tiên quyết</h1>
<p class="has-line-data" data-line-start="9" data-line-end="12">Sử dụng Python phiên bản 3.6 trở lên.<br>
sdnrecon yêu cầu các phần mềm sau:<br>
From pip3:</p>
<ul>
<li class="has-line-data" data-line-start="12" data-line-end="13">scapy</li>
<li class="has-line-data" data-line-start="13" data-line-end="14">netifaces</li>
<li class="has-line-data" data-line-start="14" data-line-end="15">scipy</li>
<li class="has-line-data" data-line-start="15" data-line-end="16">ipcalc</li>
</ul>
<h1 class="code-line" data-line-start=16 data-line-end=17><a id="Chi_tit_cc_chc_nng_16"></a>Chi tiết các chức năng</h1>
<p class="has-line-data" data-line-start="17" data-line-end="18">Chức năng trong sdnrecon được chia thành các phần khác nhau:</p>
<ul>
<li class="has-line-data" data-line-start="18" data-line-end="25">Phát hiện mạng SDN và bộ điều kiển:
<ul>
<li class="has-line-data" data-line-start="19" data-line-end="21">multi_controller_detect.py<br>
Phát hiện ra nhiều bộ điều khiển kết nối với bộ chuyển mạch trong mạng SDN, xuất các thông tin giữa controller và switch gồm IP, Mac, cổng kết nối,…</li>
<li class="has-line-data" data-line-start="21" data-line-end="23">sdn_detect.py<br>
Xác định mạng SDN có tồn tại hay không dựa vào Round-trip Time (RTT), gói tin OpenFlow.</li>
<li class="has-line-data" data-line-start="23" data-line-end="25">controller_detect.py<br>
Phát hiện loại bộ điều khiển dựa vào website quản lý, khoảng thời gian giữa các gói tin LLDP.</li>
</ul>
</li>
<li class="has-line-data" data-line-start="25" data-line-end="30">Phát hiện máy chủ
<ul>
<li class="has-line-data" data-line-start="26" data-line-end="28">arp_scan.py<br>
Tìm ra IP, MAC của các máy chủ có tồn trong mạng được chỉ định bằng giao thức arp.</li>
<li class="has-line-data" data-line-start="28" data-line-end="30">ping_scan.py<br>
Tìm ra IP của máy chủ có tồn tại trong mạng được chỉ định bằng giao thức icmp.</li>
</ul>
</li>
<li class="has-line-data" data-line-start="30" data-line-end="33">Dò quét cổng
<ul>
<li class="has-line-data" data-line-start="31" data-line-end="33">scan_port.py<br>
Tìm ra port đang mở trên máy chủ được chỉ định, kể cả tcp và udp port.</li>
</ul>
</li>
</ul>
<h1 class="code-line" data-line-start=33 data-line-end=34><a id="Cch_s_dng_33"></a>Cách sử dụng</h1>
<p class="has-line-data" data-line-start="34" data-line-end="36">python3 &lt;tên module&gt;.py &lt;options&gt;<br>
Ví dụ: python3 scan_port.py -t 10.0.0.2 -p all</p>
</body></html>

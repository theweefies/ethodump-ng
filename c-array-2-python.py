#!/usr/bin/env python3

import sys

c_data = """
test
* Blackberry identifier, Product*/
const string_string bb_vals[] =
{
    {"0x8f000d03","BlackBerry 8110"}
  , {"0x8d000d03","BlackBerry 8120"}
  , {"0x8d001103","BlackBerry 8220"}
  , {"0x96000f03","BlackBerry 8300"}
  , {"0x8d000f03","BlackBerry 8310"}
  , {"0x84000f03","BlackBerry 8320"}
  , {"0x84000f05","BlackBerry 8350"}
  , {"0x8c000f03","BlackBerry 8520 Curve"}
  , {"0x05000f04","BlackBerry 8530 Curve"}
  , {"0x84000b03","BlackBerry 8700"}
  , {"0x84000e03","BlackBerry 8800"}
  , {"0x8d000e03","BlackBerry 8820"}
  , {"0x84001503","BlackBerry 8900 Curve"}
  , {"0x85001503","BlackBerry 8980 Curve"}
  , {"0x84000e07","BlackBerry 9000 Bold"}
  , {"0x05000d07","BlackBerry 9100/9105 Pearl"}
  , {"0x0e000f03","BlackBerry 9220 Curve"}
  , {"0x04000f07","BlackBerry 9300 Curve 3G"}
  , {"0x14000f04","BlackBerry 9310 Curve"}
  , {"0x05000f07","BlackBerry 9315/9320 Curve"}
  , {"0x0e000f04","BlackBerry 9330 Curve 3G"}
  , {"0x0c000f04","BlackBerry 9350/9370 Curve"}
  , {"0x0e001507","BlackBerry 9360 Curve"}
  , {"0x04002207","BlackBerry 9380 Curve"}
  , {"0x06001404","BlackBerry 9500 Storm"}
  , {"0x0d001404","BlackBerry 9520 Storm2"}
  , {"0x04001404","BlackBerry 9530 Storm"}
  , {"0x0c001404","BlackBerry 9550 Storm2"}
  , {"0x16000f04","BlackBerry 9620 Curve"}
  , {"0x0d000d04","BlackBerry 9630 Tour"}
  , {"0x07001504","BlackBerry 9650 Bold"}
  , {"0x05001904","BlackBerry 9670 Style"}
  , {"0x04001507","BlackBerry 9700 Bold"}
  , {"0x06000f07","BlackBerry 9720"}
  , {"0x15001507","BlackBerry 9780 Bold"}
  , {"0x26001507","BlackBerry 9790 Bold"}
  , {"0x05001807","BlackBerry 9800 Torch"}
  , {"0x0c001804","BlackBerry 9810 Torch"}
  , {"0x16001404","BlackBerry 9850 Torch"}
  , {"0x1d001404","BlackBerry 9860 Torch"}
  , {"0x07001204","BlackBerry 9900 Bold"}
  , {"0x05001204","BlackBerry 9930 Bold Touch"}
  , {"0x9600240a","BlackBerry Cafe STB100-2"}
  , {"0x9c00240a","BlackBerry Cafe STB100-5"}
  , {"0x4002607","BlackBerry Dev Alpha"}
  , {"0x8d00270a","BlackBerry Dev Alpha C"}
  , {"0x04002307","BlackBerry Dev Alpha Colt"}
  , {"0x07002e0a","BlackBerry Leap STR100-1"}
  , {"0x06002e0a","BlackBerry Leap STR100-2"}
  , {"0x0c001204","BlackBerry P'9980/P'9981 Bold"}
  , {"0x87002c0a","BlackBerry Passport SQW100-1"}
  , {"0x85002c0a","BlackBerry Passport SQW100-2"}
  , {"0x84002c0a","BlackBerry Passport SQW100-3"}
  , {"0x8f002c0a","BlackBerry Passport SQW100-4"}
  , {"0x04000d04","BlackBerry Pearl 8130"}
  , {"0x06001a06","BlackBerry PlayBook"}
  , {"0x07001a06","BlackBerry PlayBook"}
  , {"0x04001a0b","BlackBerry PlayBook 0x04001a0b"}
  , {"0xa500240a","BlackBerry Porsche Design P'9982 STK100-1"}
  , {"0xa600240a","BlackBerry Porsche Design P'9982 STK100-2"}
  , {"0x8f00270a","BlackBerry Porsche Design P'9983 SQK100-1"}
  , {"0x8e00270a","BlackBerry Porsche Design P'9983 SQK100-2"}
  , {"0x8400270a","BlackBerry Q10 SQN100-1"}
  , {"0x8500270a","BlackBerry Q10 SQN100-2"}
  , {"0x8600270a","BlackBerry Q10 SQN100-3"}
  , {"0x8d00270a","BlackBerry Q10 SQN100-3 Dev Alpha"}
  , {"0x8c00270a","BlackBerry Q10 SQN100-4"}
  , {"0x8700270a","BlackBerry Q10 SQN100-5"}
  , {"0x9600270a","BlackBerry Q20 Classic SQC100-1"}
  , {"0x9400270a","BlackBerry Q20 Classic SQC100-2"}
  , {"0x9500270a","BlackBerry Q20 Classic SQC100-3"}
  , {"0x9700270a","BlackBerry Q20 Classic SQC100-4"}
  , {"0x9c00270a","BlackBerry Q20 Classic SQC100-5"}
  , {"0x84002a0a","BlackBerry Q5 SQR100-1"}
  , {"0x85002a0a","BlackBerry Q5 SQR100-2"}
  , {"0x86002a0a","BlackBerry Q5 SQR100-3"}
  , {"0x9d00080a","BlackBerry Reference model 1080p OLED"}
  , {"0x87002a07","BlackBerry SQC100-1 Kopi"}
  , {"0x8c002a07","BlackBerry SQC100-2 Kopi"}
  , {"0x04002607","BlackBerry Z10 STL100-1"}
  , {"0x8700240a","BlackBerry Z10 STL100-2 LTE"}
  , {"0x8500240a","BlackBerry Z10 STL100-3 LTE"}
  , {"0x8400240a","BlackBerry Z10 STL100-4"}
  , {"0x04002e07","BlackBerry Z3 STJ100-1"}
  , {"0x05002e07","BlackBerry Z3 STJ100-2"}
  , {"0x8c00240a","BlackBerry Z30 STA100-1"}
  , {"0x8d00240a","BlackBerry Z30 STA100-2"}
  , {"0x8e00240a","BlackBerry Z30 STA100-3"}
  , {"0x8f00240a","BlackBerry Z30 STA100-4"}
  , {"0x9500240a","BlackBerry Z30 STA100-5"}
  , {"0xb500240a","BlackBerry Z30 STA100-6"}
  , {"0xad00240a","BlackBerry Z30 STA100-9"}
  , {"", NULL}
"""
f_open = open('bb.py','w')

f_open.write('apple_models = {\n')
pos = 0
start_print = False
while pos < len(c_data):
    if pos == 0:
        prev = -1
        cur = c_data[pos]
        next = c_data[pos + 1]
    if pos > 0:
        prev = c_data[pos -1]
        cur = c_data[pos]
        next = c_data[pos + 1] if (pos + 1) < len(c_data) else c_data[pos]
    if cur == '"' and prev == '{':
        f_open.write('"')
        start_print = True
        pos += 1
        continue
    if cur == '"' and next == '}':
        f_open.write('",\n')
        start_print = False
    if cur == ',' and next == '"':
        f_open.write(':')
        pos += 1
        continue
    
    if start_print:
        f_open.write(c_data[pos])
        if cur == '}' and prev == 'L':
            break
    pos += 1

f_open.close()
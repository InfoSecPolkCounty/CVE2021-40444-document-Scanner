from zipfile import ZipFile
import sys
import time
print('Current Python version information:'+sys.version)
print('Purpose:CVE 2021-40444 scanning documents for use of mhtml\nAuthor:Patrick Gray\nThis was made for python version 3.9.7\n\n')
print('Detects the folowing reference: mhtml, mshta, wscript, cmd, wscript, vbscript, CDATA, bin, oleObject, OLE Package, shell, and powershell')


input_file=input('Enter Path to document to process:')


def attack_detected(line):
    if len(line)> 10000:
        pass
    else:
        print('\n'+'ATTACK DETECTED'+'\n\n')
        print(line)

def scan():
    with ZipFile(input_file, 'r') as archive:
        files = archive.namelist()
        for file in files:
            content = archive.open(file)
            line = archive.read(content.name)
            line = str(line)
            
            if 'mhtml' in line:
                
                attack_detected(line=line)
            if 'mshta' in line:
                
                attack_detected(line=line)
            if 'wscript' in line:
                
                attack_detected(line=line)
            if 'cmd' in line:
                
                attack_detected(line=line)
            if 'vbscript' in line:
                
                attack_detected(line=line)
            if 'CDATA' in line:
                
                attack_detected(line=line)
            if 'bin' in line:
                
                attack_detected(line=line)
            if 'oleObject' in line:
                
                attack_detected(line=line)
            if 'OLE Package' in line:
                
                attack_detected(line=line)
            if 'shell' in line:
                
                attack_detected(line=line)
            if 'powershell' in line:
                
                attack_detected(line=line)
            if 'Shell' in line:
                
                attack_detected(line=line)
            if 'PowerShell' in line:
                
                attack_detected(line=line)
            else:
                pass
        try:
            print('Press CNTRL+C or exit the program')
            for i in range(0,10000):
                time.sleep(1)
        except KeyboardInterrupt:
            exit()
scan()

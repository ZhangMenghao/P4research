
#!/usr/bin/python
# encoding=utf-8
# Filename: put_files_hdfs.py
import datetime
import os
import threading

def execCmd():
    os.system('./infinite_wget.sh')

if __name__ == '__main__':
    
    threads = []
    

    for o in range(60):
        th = threading.Thread(target=execCmd)
        th.start()
        threads.append(th)
         
    for th in threads:
        th.join()
         

    # import os

# for i in range(20):
#     os.system('./infinite_wget.sh')
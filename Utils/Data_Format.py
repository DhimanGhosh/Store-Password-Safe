'''
Print account dictionary in following format:

Input:
{'k1' : [{'d1' : 'v1'}, {'d2' : 'v2'}], 'k2' : [{'d3' : 'v3'}]}


Output:
1. k1
    i.  ID:     d1
        PASS:   v1

    ii. ID:     d2
        PASS:   v2

2. k2
    i.  ID:     d3
        PASS:   v3
'''
import os

os.chdir(os.path.dirname(os.path.realpath(__file__)))
from Utils.Numerical_Convert import Numerical_Convert

class Account_Format:
    def __init__(self, data):
        self.__data = data
        self.__nc = Numerical_Convert()

    def format_cred(self, cred_id, cred_password):
        print(f'ID:\t{cred_id}')
        print(f'\t\tPASS:\t{cred_password}\n')

    def format_apps_creds(self, data):
        for i,cred in enumerate(data):
            print(f'\t    {self.__nc.int_to_roman(i+1)}.  ', end='')
            cred_id, cred_password = list(cred.items())[0]
            self.format_cred(cred_id=cred_id, cred_password=cred_password)

    def format_account(self):
        apps = list(self.__data.keys())
        for i,app in enumerate(apps):
            creds = self.__data[app]
            print(f'\t{i+1}. {app}')
            self.format_apps_creds(creds)

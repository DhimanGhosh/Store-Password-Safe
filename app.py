'''
Handles GUI App
'''
import base64
import ast
import pickle
import os
import random
import smtplib
from stdiomask import getpass
from glob import glob
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

root_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(root_dir)
from Utils.DataStructures_Similarity import DS_Similarity
from Utils.Data_Format import Account_Format

__app__ = 'StorePasswordSafe'
retry = 3

class Utils:
    def __init__(self):
        pass

    def keygen(self, user='admin', password='admin'):
        """Generate a key for a particular user

        Keyword Arguments:
            user {username} -- name of the user (default: {'admin'})
            password_provided {password} -- password_provided_by_user (default: {str(dict())})

        Returns:
            encoded_key -- returns the key for the 'password_provided'
        """
        password = password.encode()
        salt = b'\x1c\xc0\xd9\x0cd\xda;N/\xd88t\x1a\xcam\xf1'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        with open('key_{}.pkl'.format(user), 'wb') as f:
            pickle.dump(key, f)
        return key

    def dictionary_similarity_check(self, dict1, dict2):
        """check for similarity between 2 dictionaries

        Args:
            dict1 (dict): first dictionary
            dict2 (dict): second dictionary

        Returns:
            bool: return 'True' if both dictionaries are same else 'False'
        """
        ds = DS_Similarity(dict1, dict2)
        return ds.ds_sim()

    def accounts_print(self, account_details):
        af = Account_Format(account_details)
        af.format_account()

    def app_creds_print(self, apps_creds):
        af = Account_Format(apps_creds)
        af.format_apps_creds(apps_creds)

    def creds_print(self, id, password):
        af = Account_Format({id : password})
        print('', end='\t\t')
        af.format_cred(cred_id=id, cred_password=password)


class Account_Management:
    def __init__(self):
        self.__app = __app__
        self.__no_list = ['n', 'no']
        self.__yes_list = ['y', 'yes']
        self.__id_list = ['i', 'id']
        self.__password_list = ['p', 'pwd', 'pass', 'password']
        self.__utils = Utils()
        with open(root_dir + os.sep + 'assets' + os.sep + 'recovery_Q.txt', 'r') as f:
            recovery_Q = f.readlines()
        self.__recovery_Q = [question.strip('\n') for question in recovery_Q]
        self.add_user()

    def add_user(self, user='admin', password='admin', recovery_Q='', recovery_A='', recovery_Email=''): # Check for password can't be empty while adding 'user'
        ## INCOMPLETE #NOTE:Store email id and verify using otp
        self.__user_credentials = {user : {"password" : password, "recovery_Q" : recovery_Q, "recovery_A" : recovery_A, "recovery_Email" : recovery_Email}}
        key = self.__utils.keygen(user=self.__app, password=self.__app)
        if not glob('encrypted_{}.pkl'.format(self.__app)): # Create 'StorePasswordSafe' and add 'admin' credentials
            data = {self.__app : {user : self.__user_credentials[user]}, "Users" : {}}
            self.encrypt_and_store(data=data, key=key, encrypt_file=self.__app)
        else: # open and append 'user' credentials
            existing_account_details = self.decrypt_and_retrieve(key=key, encrypt_file=self.__app)
            users = list(existing_account_details[self.__app].keys())
            if user in users and user != 'admin':
                print(f"User {user} exist!")
            else:
                existing_account_details[self.__app][user] = self.__user_credentials[user]
                existing_account_details["Users"][user] = {}
                print(f"User {user} Added Successfully!")
            self.encrypt_and_store(data=existing_account_details, key=key, encrypt_file=self.__app)

    def verify_user(self, user, password):
        existing_account_details = self.decrypt_and_retrieve(key=self.__utils.keygen(user=self.__app, password=self.__app), encrypt_file=self.__app)
        users = list(existing_account_details[self.__app].keys())
        if user in users: # 'user' exist
            if existing_account_details[self.__app][user]['password'] == password: # 'password' matched
                return (True, 'Credentials Matched')
            else:
                return (False, f'Incorrect Password for {user}')
        else:
            return (False, f'Invalid username!')

    def remove_user(self, user, password): # Remove User data along with user
        key = self.__utils.keygen(user=self.__app, password=self.__app)
        existing_account_details = self.decrypt_and_retrieve(key=key, encrypt_file=self.__app)
        users = list(existing_account_details[self.__app].keys())
        if user in users: # 'user' exist
            if existing_account_details[self.__app][user]['password'] == password: # 'password' matched
                if user in existing_account_details["Users"].keys() and user != 'admin': # to prevent deleting 'admin' data
                    del existing_account_details[self.__app][user]
                    del existing_account_details["Users"][user]
                    if glob('encrypted_{}.pkl'.format(user)):
                        os.remove('encrypted_{}.pkl'.format(user))
                    if glob('key_{}.pkl'.format(user)):
                        os.remove('key_{}.pkl'.format(user))
                    print(f"User {user} Removed Successfully!")
                    self.encrypt_and_store(data=existing_account_details, key=key, encrypt_file=self.__app)
            else:
                print(f'Incorrect Password for {user}')
        else:
            print(f'{user} does not exist!')

    def encrypt_and_store(self, data, key, encrypt_file):
        encoded_data = str(data).encode()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(encoded_data)
        with open('encrypted_{}.pkl'.format(encrypt_file), 'wb') as f:
            pickle.dump(encrypted_data, f)
        return encoded_data

    def decrypt_and_retrieve(self, key, encrypt_file): # check 'user' exists and 'password' matches with decrypted-value
        with open('encrypted_{}.pkl'.format(encrypt_file), 'rb') as f:
            encrypted_data = pickle.load(f)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        return ast.literal_eval(decrypted_data.decode())

    def user_input(self, recovery=False): #NOTE: Give support for multiple questions
        while True:
            user = input('Enter Username:\t')
            pwd = getpass('Enter Password:\t', mask='*')
            if recovery:
                recovery_Q = self.__recovery_Q[random.randint(0, len(self.__recovery_Q) - 1)]
                recovery_A = input(f'Recovery Question:\t\t{recovery_Q}\nRecovery Answer:\t\t').lower()
                recovery_Email = input(f'Recovery Email ID:\t\t').lower()
            if not recovery and (user == '' or pwd == ''):
                print('Username / Password cannot be empty!')
                continue
            elif recovery and (user == '' or pwd == '' or recovery_A == '' or recovery_Email == ''):
                print('Username / Password / Recovery-Answer / Recovery Email cannot be empty!')
                continue
            break
        if not recovery:
            return (user, pwd)
        else:
            OTP_generated = self.generateOTP()
            self.send_email(otp=OTP_generated, receiver_mail_id=recovery_Email)
            #print(f'OTP to send through mail: {OTP_generated}') ## INCOMPLETE: #NOTE: Send OTP through email
            OTP_verify = input(f'Enter the OTP received on Email:\t').strip()
            if OTP_generated == OTP_verify:
                print(f'Email {recovery_Email} verified!')
            else:
                #print('Incorrect OTP Entered!\nYou can only recover account with Recovery Answer!')
                print('Incorrect OTP Entered!\nTry Registering again!')
                #recovery_Email = ''
                self.user_input(recovery=True)
            return (user, pwd, recovery_Q, recovery_A, recovery_Email)

    def register(self): ## INCOMPLETE #NOTE: Accept email id and verify using otp
        print('\n-- REGISTER --')
        user, password, recovery_Q, recovery_A, recovery_Email = self.user_input(recovery=True)
        self.add_user(user=user, password=password, recovery_Q=recovery_Q, recovery_A=recovery_A, recovery_Email=recovery_Email)
        self.login(user=user, password=password, from_reg=True)

    def login(self, user='', password='', from_reg=False, after_sub_task=False): #NOTE: for invalid user (Re-Login / Register)
        global retry
        if user == '' or password == '':
            print('\n-- LOGIN --')
            user, password = self.user_input()
        verify_user = self.verify_user(user=user, password=password)
        if verify_user[0]:
            if not from_reg and not after_sub_task:
                print(f'\nWelcome back {user} to {__app__}!')
            else:
                print(f'\nWelcome {user} to {__app__}!')
        else:
            print(verify_user[1])
            if 'Incorrect Password' in verify_user[1]:
                new_password = ''
                while retry > 1:
                    rec_login = input('Recover Account / Try Login Again? (R/L): ').lower()
                    if rec_login == 'r':
                        new_password = self.recover_account(user=user) # Password Recovery
                        break
                    elif rec_login == 'l':
                        retry -= 1
                        self.login()
                retry = 3
                if new_password == '':
                    new_password = self.recover_account(user=user)
                self.login(user=user, password=new_password)
            elif 'Invalid username' in verify_user[1]:
                self.register()
        d = Driver()
        if user == 'admin':
            admin_menu = '''
                1. See Users
                2. Remove User
                3. Change 'admin' password
                4. Logout
            '''
            ch = int(input(admin_menu + '\nEnter Choice: '))
            if 1 <= ch <= 4: # valid choice
                if ch == 1:
                    existing_account_details = self.decrypt_and_retrieve(key=self.__utils.keygen(user=self.__app, password=self.__app), encrypt_file=self.__app)
                    users_list = list(existing_account_details[self.__app].keys())
                    if 'admin' in users_list:
                        users_list.remove('admin')
                    print(f'\n\t-- Users --')
                    if len(users_list) > 0:
                        for i,usr in enumerate(users_list):
                            print(f'\t{i+1}. {usr}')
                    else:
                        print('\tNo Users Found!')
                    self.login(user=user, password=password, after_sub_task=True)
                elif ch == 2:
                    existing_account_details = self.decrypt_and_retrieve(key=self.__utils.keygen(user=self.__app, password=self.__app), encrypt_file=self.__app)
                    users_list = list(existing_account_details[self.__app].keys())
                    if 'admin' in users_list:
                        users_list.remove('admin')
                    print(f'\n\t-- Users --')
                    if len(users_list) > 0:
                        for i,usr in enumerate(users_list):
                            print(f'\t{i+1}. {usr}')
                        user_choice_to_remove = int(input('\nEnter Choice: '))
                        if 1 <= user_choice_to_remove <= len(users_list):
                            user_to_remove = users_list[user_choice_to_remove - 1]
                            self.remove_user(user=user_to_remove, password=existing_account_details[self.__app][user_to_remove]['password'])
                    else:
                        print('\tNo Users Found!')
                    self.login(user=user, password=password, after_sub_task=True)
                elif ch == 3:
                    new_password = self.change_user_password(user=user, old_password=password)
                    self.login(user=user, password=new_password, after_sub_task=True)
                elif ch == 4:
                    print('Goodbye Admin!')
                    d.run()
                else:
                    print('Invalid Option')
                    self.login(user=user, password=password, after_sub_task=True)
        else:
            user_menu = '''
                1. Add App Details
                2. View App Details
                3. Change App Credentials
                4. Remove App Credentials
                5. Logout
                6. Change password
                7. De-Activate Account
            '''
            ch = int(input(user_menu + '\nEnter Choice: '))
            if 1 <= ch <= 7: # valid choice
                if ch == 1:
                    self.add_user_app_data(user=user, password=password)
                    self.login(user=user, password=password, after_sub_task=True)
                elif ch == 2:
                    print(f'\n\t-- Apps Stored --')
                    self.view_user_app_data(user=user, password=password)
                    self.login(user=user, password=password, after_sub_task=True)
                elif ch == 3:
                    self.change_app_credentials(user=user, password=password)
                    self.login(user=user, password=password, after_sub_task=True)
                elif ch == 4:
                    self.remove_app_credentials(user=user, password=password)
                    self.login(user=user, password=password, after_sub_task=True)
                elif ch == 5:
                    print('Logged out Successfully!\nSee you soon!')
                    d.run()
                elif ch == 6:
                    new_password = self.change_user_password(user=user, old_password=password)
                    self.login(user=user, password=new_password, after_sub_task=True)
                elif ch == 7:
                    sure = input('Do you really like to de-activate account? (N): ').lower()
                    if sure == '' or sure in self.__no_list:
                        self.login(user=user, password=password, after_sub_task=True)
                    elif sure in self.__yes_list:
                        self.remove_user(user=user, password=password)
                        d.run()
                else:
                    print('Invalid Option')
                    self.login(user=user, password=password, after_sub_task=True)

    def add_user_app_data(self, user, password, app_name='', app_id='', app_password='', from_change_app_credentials=False):
        if not from_change_app_credentials:
            while True:
                app_name = input('App Name:\t')
                app_id = input('App ID:\t\t')
                app_password = getpass('App Password:\t', mask='*')
                if app_name == '' or app_id == '' or app_password == '':
                    print('App Name/App ID/App Password cannot be empty!')
                    continue
                break
        app_user_credentials = {app_id : app_password}
        key = self.__utils.keygen(user=user, password=password)
        if not glob('encrypted_{}.pkl'.format(user)):
            self.encrypt_and_store(data={}, key=key, encrypt_file=user)
        existing_user_data = self.decrypt_and_retrieve(key=key, encrypt_file=user)
        if app_name in list(existing_user_data.keys()):
            existing_user_data[app_name].append(app_user_credentials)
        else:
            existing_user_data[app_name] = [app_user_credentials]
        encrypted_data = self.encrypt_and_store(data=existing_user_data, key=key, encrypt_file=user)
        existing_account_details = self.decrypt_and_retrieve(key=self.__utils.keygen(user=self.__app, password=self.__app), encrypt_file=self.__app)
        existing_account_details['Users'][user] = {encrypted_data} # Store 'encrypted_data' for user in app list

    def view_user_app_data(self, user, password):
        if not glob('encrypted_{}.pkl'.format(user)):
            print('\tNo App Found!')
        else:
            key = self.__utils.keygen(user=user, password=password)
            existing_user_data = self.decrypt_and_retrieve(key=key, encrypt_file=user)
            self.__utils.accounts_print(existing_user_data)

    def change_app_credentials(self, user, password):
        if not glob('encrypted_{}.pkl'.format(user)):
            print('\tNo App Found!')
        else:
            key = self.__utils.keygen(user=user, password=password)
            existing_user_data = self.decrypt_and_retrieve(key=key, encrypt_file=user)
            print(f'\n\t-- Apps Stored --')
            self.view_user_app_data(user=user, password=password)
            selected_app_number = int(input('\n\tEnter App Number: '))
            selected_app = list(existing_user_data.keys())[selected_app_number - 1]
            print(f'\tApp Selected: {selected_app}')
            selected_app_creds = existing_user_data[selected_app]
            self.__utils.app_creds_print(selected_app_creds)
            selected_cred_number = int(input('\n\tEnter Credentials Number: '))
            selected_cred = list(selected_app_creds)[selected_cred_number - 1]
            print(f'\tCreds Selected:')
            sel_app_id, sel_app_password = list(selected_cred.items())[0]
            self.__utils.creds_print(id=sel_app_id, password=sel_app_password)
            ch_id_pwd = input('\n\tWhat to change? (I/P): ').lower()
            if ch_id_pwd in self.__id_list:
                new_id = input('\n\tNew App ID: ')
                self.remove_app_credentials(user=user, password=password, app_name=selected_app, old_credentials={sel_app_id : sel_app_password}, from_change_app_credentials=True)
                self.add_user_app_data(user=user, password=password, app_name=selected_app, app_id=new_id, app_password=sel_app_password, from_change_app_credentials=True)
            elif ch_id_pwd in self.__password_list:
                new_password = getpass('\n\tNew App Password: ', mask='*')
                self.remove_app_credentials(user=user, password=password, app_name=selected_app, old_credentials={sel_app_id : sel_app_password}, from_change_app_credentials=True)
                self.add_user_app_data(user=user, password=password, app_name=selected_app, app_id=sel_app_id, app_password=new_password, from_change_app_credentials=True)

    def remove_app_credentials(self, user, password, app_name='', old_credentials={}, from_change_app_credentials=False):
        if not glob('encrypted_{}.pkl'.format(user)):
            print('\tNo App Found!')
        else:
            key = self.__utils.keygen(user=user, password=password)
            existing_user_data = self.decrypt_and_retrieve(key=key, encrypt_file=user)
            if not from_change_app_credentials:
                print(f'\n\t-- Apps Stored --')
                self.view_user_app_data(user=user, password=password)
                selected_app_number = int(input('\n\tEnter App Number: '))
                selected_app = list(existing_user_data.keys())[selected_app_number - 1]
                print(f'\tApp Selected: {selected_app}')
            else:
                selected_app = app_name
            selected_app_creds = existing_user_data[selected_app]
            if not from_change_app_credentials:
                self.__utils.app_creds_print(selected_app_creds)
                selected_cred_number = int(input('\n\tEnter Credentials Number: '))
                selected_cred = list(selected_app_creds)[selected_cred_number - 1]
                print(f'\tCreds Selected:')
            else:
                selected_cred = old_credentials
            sel_app_id, sel_app_password = list(selected_cred.items())[0]
            if not from_change_app_credentials:
                self.__utils.creds_print(id=sel_app_id, password=sel_app_password)
                sure = input('Do you really like to delete this? (N): ').lower()
            else:
                sure = 'y'
            if sure in self.__yes_list:
                creds = existing_user_data[selected_app]
                tot_creds = len(creds)
                for i in range(len(creds)):
                    app_id, app_password = list(creds[i].items())[0]
                    if app_id == sel_app_id or app_password == sel_app_password:
                        del existing_user_data[selected_app][i]
                        if tot_creds == 1:
                            del existing_user_data[selected_app]
                        break
                self.encrypt_and_store(data=existing_user_data, key=key, encrypt_file=user)

    def change_user_password(self, user, old_password):
        if self.verify_user(user=user, password=old_password)[0]:
            while True:
                new_password = getpass('\tNew Password:\t', mask='*')
                if new_password == '':
                    print('\tNew Password cannot be empty')
                    continue
                elif new_password == old_password:
                    print('\tNew Password cannot be same as old')
                    continue
                break
            existing_account_details = self.decrypt_and_retrieve(key=self.__utils.keygen(user=self.__app, password=self.__app), encrypt_file=self.__app)
            users = existing_account_details[self.__app]
            for u in users:
                if u == user:
                    existing_account_details[self.__app][user]['password'] = new_password
                    break
            self.encrypt_and_store(data=existing_account_details, key=self.__utils.keygen(user=self.__app, password=self.__app), encrypt_file=self.__app)
            return new_password

    def recover_account(self, user):
        global retry
        existing_account_details = self.decrypt_and_retrieve(key=self.__utils.keygen(user=self.__app, password=self.__app), encrypt_file=self.__app)
        recovery_Q = existing_account_details[self.__app][user]['recovery_Q']
        print('\n-- Recover Account --')
        new_password = ''
        while retry > 0:
            recovery_A = input(f'Recovery Question:\t{recovery_Q}\nRecovery Answer:\t').lower()
            if recovery_A == '':
                print('nRecovery Answer cannot be empty!')
                continue
            else:
                if existing_account_details[self.__app][user]['recovery_A'] == recovery_A:
                    new_password = self.change_user_password(user=user, old_password=existing_account_details[self.__app][user]['password'])
                    break
                retry -= 1
        retry = 3
        if new_password != '':
            print('Your Password changed successfully!\nLogging in...')
        else: ## INCOMPLETE #NOTE: Incorrect 'Recovery Answer' -->> Email Option / answer another question asked during registration
            if existing_account_details[self.__app][user]['recovery_Email'] != '':
                OTP_generated = self.generateOTP()
                self.send_email(otp=OTP_generated, receiver_mail_id=existing_account_details[self.__app][user]['recovery_Email'])
                #print(f'OTP to send through mail: {OTP_generated}') ## INCOMPLETE: #NOTE: Send OTP through email
                OTP_verify = input(f'Enter the OTP received on Email {existing_account_details[self.__app][user]["recovery_Email"]}:\t').strip()
                if OTP_generated == OTP_verify:
                    new_password = self.change_user_password(user=user, old_password=existing_account_details[self.__app][user]['password'])
                else:
                    print('Incorrect OTP Entered!')
            else:#NOTE: Handle null password after this; if recovery email not verified for user (will not get stored) [they will need to re-register if OTP not verified]
                print('Recovery Email Not found!\nUnable to to recover Account!')
        return new_password

    def generateOTP(self):
        l = [str(n) for n in range(1,10)]
        random.shuffle(l)
        return ''.join(l[:6])

    def send_email(self, otp, receiver_mail_id): #NOTE: Email validilty; Email structure correction; email duplicacy check
        s = smtplib.SMTP(host='smtp.gmail.com', port=587, timeout=30)
        s.starttls()
        admin_mail_id = 'pythonmaildg@gmail.com'
        admin_mail_pwd = 'startup4few4'
        s.login(admin_mail_id, admin_mail_pwd)
        s.sendmail(admin_mail_id, receiver_mail_id, otp)
        s.quit()


class Driver:
    def run(self): # APP Home Screen
        login_register_menu = f'''
        Welcome to {__app__}
            1. Login
            2. Register
            3. Close App
        '''
        # Login/Register 'user'
        lr = int(input(login_register_menu + '\nEnter Choice: '))
        if 1 <= lr <= 3: # valid choice
            am = Account_Management()
            if lr == 1: # login
                am.login()
                self.run()
            elif lr == 2: # register
                am.register()
                self.run()
            elif lr == 3: # exit app
                print('Good Bye!')
                exit()


if __name__ == "__main__":
    os.chdir(root_dir + os.sep + 'assets')
    d = Driver()
    d.run()

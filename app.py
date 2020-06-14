'''
Handles GUI App
'''
import base64
import ast
import pickle
import os
from stdiomask import getpass
from glob import glob
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

#os.chdir(os.path.realpath('Store-Password-Safe'))
root_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(root_dir)
from Utils.DataStructures_Similarity import DS_Similarity
from Utils.Data_Format import Account_Format

__app__ = 'StorePasswordSafe'

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
            #print(f"Key to write: {key}")
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
        self.add_user()

    def add_user(self, user='admin', password='admin'): # Check for password can't be empty while adding 'user'
        self.__user_credentials = {user : password}
        #print(f"self.__user_credentials: {self.__user_credentials}")
        key = self.__utils.keygen(user=self.__app, password=self.__app)
        if not glob('encrypted_{}.pkl'.format(self.__app)): # Create 'StorePasswordSafe' and add 'admin' credentials
            data = {self.__app : [self.__user_credentials], "Users" : {}}
            self.encrypt_and_store(data=data, key=key, encrypt_file=self.__app)
        else: # open and append 'user' credentials
            existing_account_details = self.decrypt_and_retrieve(key=key, encrypt_file=self.__app)
            if any(user in credentials.keys() for credentials in existing_account_details[self.__app]): # 'user' exist
                if user != 'admin':
                    print(f"User {user} exist!")
            else:
                existing_account_details[self.__app].append(self.__user_credentials)
                existing_account_details["Users"][user] = {}
                print(f"User {user} Added Successfully!")
            #print(f"existing_account_details: {existing_account_details}")
            self.encrypt_and_store(data=existing_account_details, key=key, encrypt_file=self.__app)

    def verify_user(self, user, password):
        user_credentials = {user : password}
        existing_account_details = self.decrypt_and_retrieve(key=self.__utils.keygen(user=self.__app, password=self.__app), encrypt_file=self.__app)
        if any(user in credentials.keys() for credentials in existing_account_details[self.__app]): # 'user' exist
            if any(credentials == user_credentials for credentials in existing_account_details[self.__app]): # 'password' matched -->> # Proceed for Login
                return (True, 'Credentials Matched')
            else:
                return (False, f'Incorrect Password for {user}')
        else:
            return (False, f'{user} does not exist!')

    def remove_user(self, user, password): # Remove User data along with user
        user_credentials = {user : password}
        key = self.__utils.keygen(user=self.__app, password=self.__app)
        existing_account_details = self.decrypt_and_retrieve(key=key, encrypt_file=self.__app)
        if any(user in credentials.keys() for credentials in existing_account_details[self.__app]): # 'user' exist
            if any(credentials == user_credentials for credentials in existing_account_details[self.__app]): # 'password' matched
                if user in existing_account_details["Users"].keys() and user != 'admin': # to prevent deleting 'admin' data
                    existing_account_details[self.__app].remove(user_credentials)
                    del existing_account_details["Users"][user]
                    if glob('encrypted_{}.pkl'.format(user)):
                        os.remove('encrypted_{}.pkl'.format(user))
                    if glob('key_{}.pkl'.format(user)):
                        os.remove('key_{}.pkl'.format(user))
                    print(f"User {user} Removed Successfully!")
                    #print(f"existing_account_details: {existing_account_details}")
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

    def user_input(self):
        while True:
            user = input('Enter Username:\t')
            pwd = getpass('Enter Password:\t', mask='*')
            if user == '' or pwd == '':
                print('Username/Password cannot be empty!')
                continue
            break
        return (user, pwd)

    def register(self):
        print('\n-- REGISTER --')
        user, password = self.user_input()
        self.add_user(user=user, password=password)
        self.login(user=user, password=password, from_reg=True)

    def login(self, user='', password='', from_reg=False, after_sub_task=False):
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
                user, password = self.user_input()
                self.login(user=user, password=password)
            elif 'does not exist' in verify_user[1]:
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
                    key = self.__utils.keygen(user=self.__app, password=self.__app)
                    existing_account_details = self.decrypt_and_retrieve(key=key, encrypt_file=self.__app)
                    users_list = [list(credentials.keys())[0] for credentials in existing_account_details[self.__app]]
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
                    key = self.__utils.keygen(user=self.__app, password=self.__app)
                    existing_account_details = self.decrypt_and_retrieve(key=key, encrypt_file=self.__app)
                    users_list = [list(credentials.keys())[0] for credentials in existing_account_details[self.__app]]
                    if 'admin' in users_list:
                        users_list.remove('admin')
                    print(f'\n\t-- Users --')
                    if len(users_list) > 0:
                        for i,usr in enumerate(users_list):
                            print(f'\t{i+1}. {usr}')
                        user_choice_to_remove = int(input('\nEnter Choice: '))
                        if 1 <= user_choice_to_remove <= len(users_list):
                            user_to_remove = users_list[user_choice_to_remove - 1]
                            key = self.__utils.keygen(user=self.__app, password=self.__app)
                            existing_account_details = self.decrypt_and_retrieve(key=key, encrypt_file=self.__app)
                            for credentials in existing_account_details[self.__app]:
                                if user_to_remove in list(credentials.keys())[0]:
                                    user_creds = credentials
                                    break
                            self.remove_user(user=user_to_remove, password=user_creds[user_to_remove])
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
                # app_user_new_credentials = {new_id : sel_app_password}
                self.remove_app_credentials(user=user, password=password, app_name=selected_app, old_credentials={sel_app_id : sel_app_password}, from_change_app_credentials=True)
                self.add_user_app_data(user=user, password=password, app_name=selected_app, app_id=new_id, app_password=sel_app_password, from_change_app_credentials=True)
            elif ch_id_pwd in self.__password_list:
                new_password = getpass('\n\tNew App Password: ', mask='*')
                # app_user_new_credentials = {sel_app_id : new_password}
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
                new_password = getpass('\ttNew Password:\t', mask='*')
                if new_password == '':
                    print('\tNew Password cannot be empty')
                    continue
                elif new_password == old_password:
                    print('\tNew Password cannot be same as old')
                    continue
                break
            key = self.__utils.keygen(user=self.__app, password=self.__app)
            existing_account_details = self.decrypt_and_retrieve(key=key, encrypt_file=self.__app)
            creds = existing_account_details[self.__app]
            for i in range(len(creds)):
                user_id, user_password = list(creds[i].items())[0]
                if user_id == user or user_password == old_password:
                    existing_account_details[self.__app][i][user] = new_password
                    break
            self.encrypt_and_store(data=existing_account_details, key=key, encrypt_file=self.__app)
            return new_password

    def password_hint(self): ## INCOMPLETE #NOTE: Store Password hint (Q & A) for each user (controlled by admin)
        pass

    def recover_password(self): ## INCOMPLETE #NOTE: Store Password hint (Q & A) for each user (controlled by admin)
        pass


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

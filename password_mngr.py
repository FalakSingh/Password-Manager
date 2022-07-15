#!/usr/bin/env python3


import os
import hashlib
from cryptography.fernet import Fernet
import getpass
import json
import base64
import time
#Class for encrypting and decrypting text
class Crypto:
    def generate_key(self):
        return Fernet.generate_key()
        
    def encrypt(self, data, key):
        crypt_object = Fernet(key)
        encrypted_code = crypt_object.encrypt(data)
        return encrypted_code

    def decrypt(self, data, key):
        crypt_object = Fernet(key)
        decrypted_code = crypt_object.decrypt(data)
        return decrypted_code

class Pass_Main:

	def __init__(self):
		self.key = b'-ZE7SwuXrh0sr_F3gVtkBTuFWFygfO4wylYCIGp3zyw='
	def screen_clear(self):
		try:
			os.system("clear")
		except:
			os.system("cls")

	def greeting(self):
		self.screen_clear()
		logo ='''

		#### PASSWORD MANAGER ####
		'''
		print(logo)

	def init_check(self):
		cwd = os.getcwd()
		if os.path.exists(cwd+"/db_file.json") == False:
			access_pass = getpass.getpass("Please Enter to Password that you'll be using to access the program: ")
			self.screen_clear()
			access_pass_check = getpass.getpass("Please Confirm the Password: ")
			self.screen_clear()
			if access_pass == access_pass_check:
				print("Password Saved:",access_pass)
				hash_passwd = hashlib.sha256(access_pass.encode())
				str_hash_passwd = str(hash_passwd.hexdigest())
				passwd = Crypto().encrypt(str_hash_passwd.encode(),self.key)
				with open('db_file.json', 'w') as db_file:
					db_file.write(passwd.decode())
			time.sleep(2)
		with open("db_file.json","r") as db_file:
			db_list = db_file.readlines()
			if not db_list:
				os.remove("db_file.json")
				self.init_check()
		for item in db_list:
			if item == "\n":
				db_list.remove(item)
				with open("db_file.json","w") as db_file:
					for item in db_list:
						db_file.write(item)


	def encrypt(self,website,email,username,password):
		db_dict = {'Website':website, 'Email':email, 'Username':username, 'Password':password}
		json_dict = json.dumps(db_dict).encode()
		fernet_encrypted = Crypto().encrypt(json_dict,self.key)
		hex_converted = fernet_encrypted.hex()
		base64_encoded = base64.b64encode(hex_converted.encode())
		final_encrypted = base64_encoded
		with open('db_file.json', 'a') as db_file:
			db_file.write("\n")
			db_file.write(json.dumps(final_encrypted.decode()))
	
	def decrypt(self):
		with open('db_file.json', 'r') as db_file:
			entries_list = db_file.readlines()[1:]
			final_list = []
		for elements in entries_list:
			base64_decoded = base64.b64decode(elements).decode()
			hex_decoded = bytearray.fromhex(base64_decoded).decode()
			fernet_decrypted = Crypto().decrypt(hex_decoded.encode(),self.key)
			decrypted_dict = json.loads(fernet_decrypted)
			final_list.append(decrypted_dict)
		return final_list


	#1st option to create a password entery
	def create_pass(self):
		self.greeting()
		print("[*] Creating New Password Entry"+"\n")
		website = input("[+] Enter the website: ")
		email = input("[+] Enter the Email id: ")
		username = input("[+] Enter the Username: ")
		password = input("[+] Enter the Password: ")
		if not website: website = "None"
		if not email: email = "None"
		if not username: username = "None"
		if not password: print("[-] No password given \nReturning to Main Menu"), time.sleep(3)
		if website == email == username == "None":
			print("\n"+"[-] Sorry combination not allowed. Try again") , time.sleep(3)
			self.options_screen()
		self.encrypt(website,email,username,password)

	#2nd option to look for specific password entry
	def single_passwd(self):
		self.greeting()
		passwd_list = self.decrypt()
		check = None
		query = input("[+] Please Enter Search Query: ")
		for dic in passwd_list:
			for elements in dic:
				if query in dic[elements]:
					print("Website:"+dic["Website"])
					print("Email:"+dic["Email"])
					print("Username:"+dic["Username"])
					print("Password:"+dic["Password"])
					print("\n")
					check = True
		if check != True:
			print("\n[-] Sorry no entry matches your keyword")

		if_read_check = input("(Press 'Enter' when done)")

	#3rd option to show each and every password
	def show_passwd(self,passwd_list):
		self.greeting()
		entry_no = 1
		for dic in passwd_list:
			print(f"[{entry_no}]:Password Entry\n"+"----------------------------------")
			entry_no += 1
			for elements in dic:        
				print("(*)"+elements + ":" + dic[elements])
			print("\n")
		if_read_check = input("(Press 'Enter' when done)")

	#4th option to delete a password entry
	def del_passwd(self):
		self.greeting()
		print("[*] Please find the Password Entry you want to Delete\n")
		self.show_passwd(self.decrypt())
		print("[*] Please find the Password Entry you want to Delete\n")
		try:
			str_inp_entries = (input("[+] Input the Entry you want to Delete(if multiple seperate them with space): ")).split()
		except ValueError:
			self.screen_clear()
			print("[-]Error, Please Enter only Integers")
			time.sleep(2)
			self.del_passwd()
		if not str_inp_entries:
			print("No input given. Exiting...")
			time.sleep(2)
			exit()
		passwd_list = self.decrypt()
		print("[+] Following Entry/Entries will be deleted")
		for entry in (str_inp_entries):
			dictionary = passwd_list[int(entry)-1]
			print(f"\n[{entry}]: Password Entry\n------------------------------")
			for dict_elements in dictionary:
				print(dict_elements + ":" + dictionary[dict_elements])
		check = input("\n[ Press Enter to Confirm ]")
		try:
			with open("db_file.json","r") as db_file:
				passwd_list = db_file.readlines()
			for entry in str_inp_entries:
				del passwd_list[int(entry)]
			with open("db_file.json", "w") as db_file:
				for stuff in passwd_list:
					if stuff == "\n":
						passwd_list.remove(stuff)
					else:
						db_file.write(stuff)
		except Exception as ex:
			pass
			print(ex)


	def main_screen(self):
		self.greeting()
		self.screen_clear()
		access_pass = getpass.getpass("Please Input Password to Proceed: ") 
		with open('db_file.json', 'r') as pass_check: passwd = pass_check.readlines()[0]
		fernet_decrypted = Crypto().decrypt(passwd.encode(),self.key)
		str_fernet_decrypted = fernet_decrypted.decode()
		hashed_pass = hashlib.sha256(access_pass.encode())
		hashed_passwd = str(hashed_pass.hexdigest())
		try:
			passwd = passwd.replace("\n","")	
		except:
			pass
		if str_fernet_decrypted != hashed_passwd: print(f"[-] Your Input:{access_pass}\n[-] Sorry wrong Password... Please try again"), exit()

	
	def options_screen(self):
		self.greeting()
		options = input("1. Create a new Password Entry \n2. Show a Password Entry \n3. Show all Passwords \n4. Delete a Password Entry\n5. Exit the program\nEnter your option: ")
		if options == "1":
			self.create_pass()
		if options == "2":
			self.single_passwd()
		if options == "3":
			self.show_passwd(self.decrypt())
		if options == "4":
			self.del_passwd()
		if options == "5":
			print("Exiting...!!!")
			time.sleep(1)
			self.screen_clear()
			exit()



	def main_execution(self):
		try:
			self.init_check()
			self.greeting()
			self.main_screen()
			while True:
				self.options_screen()
		except:
			self.init_check()
			print("\n[-] Something Went Wrong, Exiting Program")
			exit()

print(Pass_Main().main_execution())